/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, ValidationResult};
use common::{
    Server,
    auth::{AccessToken, Permissions, PermissionsGroup, permissions::BuildPermissions},
};
use directory::core::secret::{hash_secret, is_password_hash};
use jmap_proto::error::set::SetError;
use registry::{schema::structs::TaskStatus, types::datetime::UTCDateTime};
use registry::{
    schema::{
        enums::{AccountType, Permission},
        prelude::{MASKED_PASSWORD, ObjectType, Property},
        structs::{Account, Credential, Role, Task, TaskDestroyAccount},
    },
    types::EnumImpl,
};
use store::write::{BatchBuilder, RegistryClass, ValueClass, now};
use trc::AddContext;
use types::id::Id;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use registry::schema::{enums::TenantStorageQuota, prelude::ObjectInner};
#[cfg(feature = "enterprise")]
use store::registry::{RegistryObjectCounter, RegistryQuery};
// SPDX-SnippetEnd

#[derive(Clone, Copy)]
pub enum AccountUpdate<'x> {
    Update(&'x Account),
    Create(&'x str),
}

pub async fn validate_account(
    server: &Server,
    access_token: &AccessToken,
    mut account: &mut Account,
    old_account: AccountUpdate<'_>,
) -> ValidationResult {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    if server.core.is_enterprise_edition()
        && matches!(old_account, AccountUpdate::Create(_))
        && !server.can_create_account().await?
    {
        return Ok(Err(SetError::forbidden().with_description(format!(
            "Enterprise licensed account limit reached: {} accounts licensed.",
            server.licensed_accounts()
        ))));
    }
    // SPDX-SnippetEnd

    let is_external_directory = if let Account::User(account) = account {
        server
            .domain_by_id(account.domain_id.document_id())
            .await?
            .and_then(|domain| server.get_directory_for_cached_domain(&domain))
            .is_some()
    } else {
        false
    };
    let recover_account_id = if server.registry().is_recovery_mode()
        && let AccountUpdate::Create(client_id) = old_account
        && let Some(account_id) = client_id
            .strip_prefix("restore-")
            .and_then(|id| id.parse::<u32>().ok())
    {
        Some(account_id)
    } else {
        None
    };

    // Changing only group memberships or quotas doesn't require holding every
    // permission of the account being updated (see `is_directory_update`).
    if let AccountUpdate::Update(old_account) = old_account
        && !is_directory_update(account, old_account)
        && let Err(err) = validate_account_access(server, access_token, old_account).await?
    {
        return Ok(Err(err));
    }

    let validate_permissions = match (&mut account, old_account) {
        (Account::User(account), AccountUpdate::Update(Account::User(old_account))) => {
            // Validate credentials
            let has_password = account.credentials.values().any(|credential| {
                matches!(credential, Credential::Password(credential) if credential.credential_id.is_valid())
            });
            let mut max_credential_id = 0;
            let mut has_new_credentials = false;
            for credential in account.credentials.values_mut() {
                let credential_id = credential.credential_id();

                if credential_id.is_valid() && credential_id.id() > max_credential_id {
                    max_credential_id = credential_id.id();
                }

                if let Some(old_credential) = old_account
                    .credentials
                    .values()
                    .find(|c| c.credential_id() == credential_id)
                {
                    if credential != old_credential {
                        match (credential, old_credential) {
                            (
                                Credential::Password(credential),
                                Credential::Password(old_credential),
                            ) => {
                                if is_external_directory {
                                    return Ok(Err(SetError::forbidden().with_description(
                                        "Cannot change credentials for accounts in an external directory.",
                                    )));
                                }

                                // Reset the original password if the client accidentally sent the masked password
                                if credential.secret == MASKED_PASSWORD {
                                    credential.secret = old_credential.secret.clone();
                                }
                                if credential
                                    .otp_url
                                    .as_ref()
                                    .is_some_and(|otp_url| otp_url == MASKED_PASSWORD)
                                {
                                    credential.otp_url = old_credential.otp_url.clone();
                                }

                                if credential.secret != old_credential.secret {
                                    if credential.expires_at == old_credential.expires_at
                                        && credential
                                            .expires_at
                                            .is_some_and(|exp| exp.timestamp() <= now() as i64)
                                        && let Some(expires_at) =
                                            server.core.network.security.password_default_expiration
                                    {
                                        credential.expires_at = Some(UTCDateTime::from_timestamp(
                                            (now() + expires_at) as i64,
                                        ));
                                    }

                                    if !(matches!(
                                        credential.secret.as_bytes().first(),
                                        Some(&b'$' | &b'{')
                                    ) && is_password_hash(&credential.secret))
                                    {
                                        if let Err(err) =
                                            server.is_secure_password(&credential.secret, &[])
                                        {
                                            return Ok(Err(SetError::invalid_properties()
                                                .with_property(Property::Secret)
                                                .with_description(err)));
                                        }

                                        credential.secret = hash_secret(
                                            &server.inner.data.password_verifier,
                                            server.core.network.security.password_hash_algorithm,
                                            std::mem::take(&mut credential.secret).into_bytes(),
                                        )
                                        .await
                                        .caused_by(trc::location!())?;
                                    }
                                }
                            }
                            (
                                Credential::AppPassword(credential),
                                Credential::AppPassword(old_credential),
                            )
                            | (
                                Credential::ApiKey(credential),
                                Credential::ApiKey(old_credential),
                            ) => {
                                // Reset the original password if the client accidentally sent the masked password
                                if credential.secret == MASKED_PASSWORD {
                                    credential.secret = old_credential.secret.clone();
                                }

                                if credential.secret != old_credential.secret {
                                    return Ok(Err(SetError::forbidden().with_description(
                                        "Cannot change app password or API credentials through this method.",
                                    )));
                                }
                            }
                            (
                                Credential::Passkey(credential),
                                Credential::Passkey(old_credential),
                            ) => {
                                if credential.key_id != old_credential.key_id
                                    || credential.public_key != old_credential.public_key
                                    || credential.algorithm != old_credential.algorithm
                                    || credential.created_at != old_credential.created_at
                                {
                                    return Ok(Err(SetError::forbidden().with_description(
                                        "Only the name of a passkey can be changed.",
                                    )));
                                }
                            }
                            _ => {
                                return Ok(Err(SetError::invalid_properties()
                                    .with_property(Property::Credentials)
                                    .with_description("Credential type cannot be changed.")));
                            }
                        }
                    }
                } else if let Err(err) = validate_credential_creation(
                    server,
                    credential,
                    is_external_directory,
                    has_password,
                )
                .await?
                {
                    return Ok(Err(err));
                } else {
                    has_new_credentials = true;
                }
            }

            if has_new_credentials {
                for credential in account.credentials.values_mut() {
                    if !credential.credential_id().is_valid() {
                        max_credential_id += 1;
                        credential.set_credential_id(Id::from(max_credential_id));
                    }
                }
            }

            account.permissions != old_account.permissions || account.roles != old_account.roles
        }
        (Account::Group(account), AccountUpdate::Update(Account::Group(old_account))) => {
            account.permissions != old_account.permissions || account.roles != old_account.roles
        }
        (Account::User(account), AccountUpdate::Create(_)) => {
            // Validate credentials
            for (index, credential) in account.credentials.values_mut().enumerate() {
                if let Err(err) = validate_credential_creation(
                    server,
                    credential,
                    is_external_directory,
                    index > 0,
                )
                .await?
                {
                    return Ok(Err(err));
                }
                credential.set_credential_id(Id::from(index as u64));
            }

            true
        }
        (Account::Group(_), AccountUpdate::Create(_)) => true,
        (Account::User(_), AccountUpdate::Update(Account::Group(_)))
        | (Account::Group(_), AccountUpdate::Update(Account::User(_))) => {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::Type)
                .with_description(
                    "Cannot change the type of an existing account.",
                )));
        }
    };

    let mut result = if validate_permissions {
        Ok(server
            .can_set_permissions(access_token, account)
            .await?
            .map(|_| ObjectResponse::default())
            .map_err(build_set_error))
    } else {
        Ok(Ok(ObjectResponse::default()))
    };

    if let Some(account_id) = recover_account_id
        && let Ok(Ok(result)) = &mut result
    {
        restore_account_id(server, account_id).await?;
        result.id = Some(account_id.into());
    }

    result
}

pub async fn validate_account_access(
    server: &Server,
    access_token: &AccessToken,
    account: &Account,
) -> trc::Result<Result<(), SetError<Property>>> {
    server
        .can_set_permissions(access_token, account)
        .await
        .map(|result| result.map_err(build_set_error))
}

/// Whether an update changes nothing but the group memberships or quotas of a
/// user, or the quotas of a group. Such an update can't change the account's
/// permissions or roles: group IDs must name existing groups, and membership
/// gives access to the groups' data and to whatever is shared with the groups,
/// not to their permissions or roles. Any other change, to aliases (logins
/// through an external directory resolve addresses by alias), credentials,
/// roles, permissions, name, domain or anything else, still requires the caller
/// to hold every permission of the account.
pub fn is_directory_update(account: &Account, old_account: &Account) -> bool {
    match (account, old_account) {
        (Account::User(account), Account::User(old_account)) => {
            let mut account = account.clone();
            account.member_group_ids = old_account.member_group_ids.clone();
            account.quotas = old_account.quotas.clone();
            account == *old_account
        }
        (Account::Group(account), Account::Group(old_account)) => {
            let mut account = account.clone();
            account.quotas = old_account.quotas.clone();
            account == *old_account
        }
        _ => false,
    }
}

async fn validate_credential_creation(
    server: &Server,
    credential: &mut Credential,
    is_external_directory: bool,
    has_password: bool,
) -> trc::Result<Result<(), SetError<Property>>> {
    match credential {
        Credential::Password(credential) => {
            if is_external_directory {
                return Ok(Err(SetError::forbidden().with_description(
                    "Cannot set credentials for accounts in an external directory.",
                )));
            } else if has_password {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Credentials)
                    .with_description("Only one password credential is allowed.")));
            }

            if credential.expires_at.is_none()
                && let Some(expires_at) = server.core.network.security.password_default_expiration
            {
                credential.expires_at =
                    Some(UTCDateTime::from_timestamp((now() + expires_at) as i64));
            }

            if matches!(credential.secret.as_bytes().first(), Some(&b'$' | &b'{'))
                && is_password_hash(&credential.secret)
            {
                Ok(Ok(()))
            } else if let Err(err) = server.is_secure_password(&credential.secret, &[]) {
                Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Secret)
                    .with_description(err)))
            } else {
                credential.secret = hash_secret(
                    &server.inner.data.password_verifier,
                    server.core.network.security.password_hash_algorithm,
                    std::mem::take(&mut credential.secret).into_bytes(),
                )
                .await
                .caused_by(trc::location!())?;
                Ok(Ok(()))
            }
        }
        Credential::AppPassword(_) | Credential::ApiKey(_) => {
            Ok(Err(SetError::invalid_properties()
                .with_property(Property::Credentials)
                .with_description(
                    "Secondary credentials cannot be set directly.",
                )))
        }
        Credential::Passkey(_) => Ok(Err(SetError::invalid_properties()
            .with_property(Property::Credentials)
            .with_description("Passkeys can only be registered by the account owner."))),
    }
}

#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
pub(crate) async fn validate_role(
    access_token: &AccessToken,
    role: &mut Role,
    old_role: Option<&Role>,
) -> ValidationResult {
    if old_role.is_none_or(|old_role| {
        old_role.enabled_permissions != role.enabled_permissions
            || old_role.disabled_permissions != role.disabled_permissions
            || old_role.role_ids != role.role_ids
    }) {
        Ok(access_token
            .can_grant_permissions(
                PermissionsGroup {
                    enabled: Permissions::from_permission(role.enabled_permissions.as_slice()),
                    disabled: Permissions::from_permission(role.disabled_permissions.as_slice()),
                    merge: false,
                }
                .finalize(),
            )
            .map(|_| ObjectResponse::default())
            .map_err(build_set_error))
    } else {
        Ok(Ok(ObjectResponse::default()))
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub fn tenant_object_quota(object: &ObjectInner) -> Option<TenantStorageQuota> {
    match object {
        ObjectInner::Account(account) => Some(match account.as_ref() {
            Account::User(_) => TenantStorageQuota::MaxAccounts,
            Account::Group(_) => TenantStorageQuota::MaxGroups,
        }),
        ObjectInner::Domain(_) => Some(TenantStorageQuota::MaxDomains),
        ObjectInner::MailingList(_) => Some(TenantStorageQuota::MaxMailingLists),
        ObjectInner::Role(_) => Some(TenantStorageQuota::MaxRoles),
        ObjectInner::OAuthClient(_) => Some(TenantStorageQuota::MaxOauthClients),
        ObjectInner::DkimSignature(_) => Some(TenantStorageQuota::MaxDkimKeys),
        ObjectInner::DnsServer(_) => Some(TenantStorageQuota::MaxDnsServers),
        ObjectInner::Directory(_) => Some(TenantStorageQuota::MaxDirectories),
        ObjectInner::AcmeProvider(_) => Some(TenantStorageQuota::MaxAcmeProviders),
        _ => None,
    }
}

#[cfg(feature = "enterprise")]
pub async fn validate_tenant_quota(
    server: &Server,
    tenant_id: Option<u32>,
    quota: TenantStorageQuota,
) -> ValidationResult {
    if let Some(tenant_id) = tenant_id {
        let tenant = server.tenant(tenant_id).await?;
        if let Some(quotas) = tenant
            .quota_objects
            .as_ref()
            .map(|quotas| quotas.get(quota))
            .filter(|quota| *quota != u32::MAX)
        {
            let (object_type, type_filter, description) = match quota {
                TenantStorageQuota::MaxAccounts => {
                    (ObjectType::Account, Some(AccountType::User), "accounts")
                }
                TenantStorageQuota::MaxGroups => {
                    (ObjectType::Account, Some(AccountType::Group), "groups")
                }
                TenantStorageQuota::MaxDomains => (ObjectType::Domain, None, "domains"),
                TenantStorageQuota::MaxMailingLists => {
                    (ObjectType::MailingList, None, "mailing lists")
                }
                TenantStorageQuota::MaxRoles => (ObjectType::Role, None, "roles"),
                TenantStorageQuota::MaxOauthClients => {
                    (ObjectType::OAuthClient, None, "OAuth clients")
                }
                TenantStorageQuota::MaxDkimKeys => (ObjectType::DkimSignature, None, "DKIM keys"),
                TenantStorageQuota::MaxDnsServers => (ObjectType::DnsServer, None, "DNS servers"),
                TenantStorageQuota::MaxDirectories => (ObjectType::Directory, None, "directories"),
                TenantStorageQuota::MaxAcmeProviders => {
                    (ObjectType::AcmeProvider, None, "ACME providers")
                }
                TenantStorageQuota::MaxDiskQuota => unreachable!(),
            };
            let query = RegistryQuery::new(object_type).with_tenant(tenant_id.into());
            let count = if let Some(type_filter) = type_filter {
                server
                    .registry()
                    .query::<Vec<Id>>(query.equal(Property::Type, type_filter.to_id()))
                    .await?
                    .len() as u32
            } else {
                server
                    .registry()
                    .query::<RegistryObjectCounter>(query)
                    .await?
                    .0 as u32
            };

            if count >= quotas {
                return Ok(Err(SetError::over_quota().with_description(format!(
                    "You have exceeded your quota of {} {}.",
                    quotas, description
                ))));
            }
        }
    }

    Ok(Ok(ObjectResponse::default()))
}
// SPDX-SnippetEnd

pub async fn schedule_account_destruction(
    server: &Server,
    account_id: Id,
    account: &Account,
) -> trc::Result<()> {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let status = server
        .core
        .enterprise
        .as_ref()
        .and_then(|e| e.deleted_accounts_retention.as_ref())
        .map(|retention| TaskStatus::at(store::write::now() as i64 + retention.as_secs() as i64))
        .unwrap_or_else(TaskStatus::now);
    // SPDX-SnippetEnd

    #[cfg(not(feature = "enterprise"))]
    let status = TaskStatus::now();

    let (account_domain_id, account_name, account_type, member_group_ids) = match account {
        Account::User(account) => (
            account.domain_id,
            account.name.clone(),
            AccountType::User,
            account.member_group_ids.clone(),
        ),
        Account::Group(account) => (
            account.domain_id,
            account.name.clone(),
            AccountType::Group,
            Default::default(),
        ),
    };

    let mut batch = BatchBuilder::new();
    batch.schedule_task(Task::DestroyAccount(TaskDestroyAccount {
        account_domain_id,
        account_id,
        account_name,
        account_type,
        member_group_ids,
        status,
    }));

    server.commit_batch(batch).await?;

    Ok(())
}

pub(crate) fn build_set_error(permissions: Vec<Permission>) -> SetError<Property> {
    let mut missing_permissions = String::with_capacity(16);
    let mut total_missing = permissions.len();
    for permission in permissions.into_iter().take(5) {
        if !missing_permissions.is_empty() {
            missing_permissions.push_str(", ");
        }
        missing_permissions.push_str(permission.as_str());
        total_missing -= 1;
    }
    if total_missing > 0 {
        missing_permissions.push_str(&format!(" and {} more", total_missing));
    }

    SetError::forbidden().with_description(format!(
        "You are not authorized to grant permissions: {}",
        missing_permissions
    ))
}

async fn restore_account_id(server: &Server, id: u32) -> trc::Result<()> {
    // Obtain current counter value
    let object_id = ObjectType::Account.to_id();
    let last_id = server
        .store()
        .get_counter(ValueClass::Registry(RegistryClass::IdCounter { object_id }))
        .await
        .caused_by(trc::location!())?
        .cast_unsigned() as u32;

    if last_id < id {
        let mut id_batch = BatchBuilder::new();
        id_batch.add_and_get(
            ValueClass::Registry(RegistryClass::IdCounter { object_id }),
            (id - last_id) as i64,
        );
        let last_id = server
            .store()
            .write_batch(&mut id_batch)
            .await?
            .last_counter_id();

        if last_id < id as i64 {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to update id counter")
                .caused_by(trc::location!()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_directory_update;
    use registry::{
        schema::{
            enums::{Permission, StorageQuota},
            structs::{
                Account, Credential, CustomRoles, EmailAlias, GroupAccount, PasswordCredential,
                Permissions, PermissionsList, Roles, UserAccount, UserRoles,
            },
        },
        types::{list::List, map::Map},
    };
    use types::id::Id;

    fn user() -> UserAccount {
        let mut user = UserAccount {
            name: "jane".into(),
            domain_id: Id::from(1u64),
            credentials: List::from(vec![Credential::Password(PasswordCredential {
                credential_id: Id::from(0u64),
                secret: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
                ..Default::default()
            })]),
            member_group_ids: Map::new(vec![Id::from(10u64)]),
            aliases: List::from(vec![EmailAlias {
                enable: true,
                name: "j".into(),
                domain_id: Id::from(1u64),
                description: None,
            }]),
            roles: UserRoles::Admin,
            ..Default::default()
        };
        user.quotas.set(StorageQuota::MaxDiskQuota, 1 << 30);
        user
    }

    fn group() -> GroupAccount {
        let mut group = GroupAccount {
            name: "staff".into(),
            domain_id: Id::from(1u64),
            ..Default::default()
        };
        group.quotas.set(StorageQuota::MaxDiskQuota, 1 << 30);
        group
    }

    fn check_user(change: impl FnOnce(&mut UserAccount)) -> bool {
        let old = Account::User(user());
        let mut new = user();
        change(&mut new);
        is_directory_update(&Account::User(new), &old)
    }

    fn check_group(change: impl FnOnce(&mut GroupAccount)) -> bool {
        let old = Account::Group(group());
        let mut new = group();
        change(&mut new);
        is_directory_update(&Account::Group(new), &old)
    }

    fn permissions() -> Permissions {
        Permissions::Merge(PermissionsList {
            enabled_permissions: Map::new(vec![Permission::Impersonate]),
            disabled_permissions: Map::new(vec![]),
        })
    }

    #[test]
    fn directory_changes_of_a_user_are_exempt() {
        assert!(check_user(|_| {}));
        assert!(check_user(
            |u| u.member_group_ids = Map::new(vec![Id::from(10u64), Id::from(11u64)])
        ));
        assert!(check_user(|u| u.member_group_ids = Map::new(vec![])));
        assert!(check_user(|u| {
            u.quotas.set(StorageQuota::MaxDiskQuota, 0);
        }));
        assert!(check_user(|u| {
            u.member_group_ids = Map::new(vec![]);
            u.quotas.set(StorageQuota::MaxEmails, 5);
        }));
    }

    #[test]
    fn other_changes_of_a_user_need_the_full_check() {
        // Aliases
        assert!(!check_user(|u| {
            u.aliases.0.append(
                1u32,
                EmailAlias {
                    enable: true,
                    name: "jane.doe".into(),
                    domain_id: Id::from(1u64),
                    description: None,
                },
            )
        }));
        assert!(!check_user(|u| u.aliases = List::from(vec![])));
        // Credentials
        assert!(!check_user(|u| {
            if let Some(Credential::Password(p)) =
                u.credentials.0.inner.first_mut().map(|kv| &mut kv.value)
            {
                p.secret = "new password".into();
            }
        }));
        assert!(!check_user(|u| u.credentials = List::from(vec![])));
        // Roles and permissions
        assert!(!check_user(|u| u.roles = UserRoles::User));
        assert!(!check_user(|u| u.roles = UserRoles::Custom(CustomRoles {
            role_ids: Map::new(vec![Id::from(3u64)])
        })));
        assert!(!check_user(|u| u.permissions = permissions()));
        // Identity
        assert!(!check_user(|u| u.name = "john".into()));
        assert!(!check_user(|u| u.domain_id = Id::from(2u64)));
        assert!(!check_user(|u| u.description = Some("x".into())));
        // An allowed change together with another one
        assert!(!check_user(|u| {
            u.member_group_ids = Map::new(vec![]);
            u.roles = UserRoles::User;
        }));
    }

    #[test]
    fn only_quotas_of_a_group_are_exempt() {
        assert!(check_group(|_| {}));
        assert!(check_group(|g| {
            g.quotas.set(StorageQuota::MaxDiskQuota, 0);
        }));
        assert!(!check_group(|g| g.aliases = List::from(vec![EmailAlias {
            enable: true,
            name: "staff".into(),
            domain_id: Id::from(1u64),
            description: None,
        }])));
        assert!(!check_group(|g| g.permissions = permissions()));
        assert!(!check_group(|g| g.roles = Roles::Custom(CustomRoles {
            role_ids: Map::new(vec![Id::from(3u64)])
        })));
        assert!(!check_group(|g| g.name = "admins".into()));
    }

    #[test]
    fn the_account_type_cannot_change() {
        assert!(!is_directory_update(
            &Account::Group(group()),
            &Account::User(user())
        ));
        assert!(!is_directory_update(
            &Account::User(user()),
            &Account::Group(group())
        ));
    }
}
