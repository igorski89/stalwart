# igorski89/stalwart fork

A fork of [stalwartlabs/stalwart](https://github.com/stalwartlabs/stalwart) with two changes to account
updates and group creation, for a self-hosted deployment managed by an automated directory client. **Not affiliated with or
endorsed by Stalwart Labs.** For Stalwart itself, use upstream; don't report problems with this fork there.

- Branch `sgnl`, based on upstream tag `v1.1.1` (`3adead91`). Upstream isn't tracked: a new upstream
  release is merged only when needed.
- CI: `.github/workflows/sgnl-test.yml` runs the unit tests of the change and the probe against a debug
  build of the server. It builds no image and uploads no binary.
- Images are built privately and not published: `sgnl/Dockerfile` (target `gnu`, build argument
  `TARGET=x86_64-unknown-linux-gnu`) from a tag `v<upstream version>-sgnl.<n>` (for example
  `v1.1.1-sgnl.1`). It is upstream's `Dockerfile.build` without the FoundationDB binary, the musl stage and
  sccache; the builder runs on the build platform and cross-compiles with zig, as upstream's release does.
  The build features (`sqlite postgres mysql rocks s3 redis keep azure nats enterprise`) and the gnu runtime
  stage (Debian trixie-slim, user `stalwart` 2000:2000, `/etc/stalwart`, `/var/lib/stalwart`, entrypoint
  `/usr/local/bin/stalwart --config /etc/stalwart/config.json`) are upstream's, so the image replaces
  `stalwartlabs/stalwart:v1.1.1`.

## Releases

| Tag | Commit | Notes |
|---|---|---|
| `v1.1.1-sgnl.2` | `82517c21` | Creating groups with the defaults (see below). Security review; probe passed on an empty server and on a restored copy of production data (the probe's own later additions are in `374191be`); in production since 2026-11-26 |
| `v1.1.1-sgnl.1` | `106776e8` | Account updates that only change group memberships or quotas. Security review, then a delta review after aliases were removed from the exemption; probe passed on an empty server and on a restored copy of production data; in production since 2026-11-26 |

## Changes from upstream

Every file this fork modifies, adds or removes, with the date of the change (AGPL-3.0 Section 5(a)).

| Change | Files | Date |
|---|---|---|
| **Account updates that only change group memberships or quotas.** Upstream checks on every update of an account (JMAP `x:Account/set`, SCIM) that the caller holds every permission of the account being updated, so a client with `sysAccountUpdate` but fewer permissions than a user can't change that user's groups or quotas. In this fork the check is skipped when the update changes nothing but `memberGroupIds` and `quotas` of a user, or `quotas` of a group (`is_directory_update`: the new account with those fields set back to their old values must equal the old account). Any other change, alone or with an allowed change, still runs the full check: aliases (a login through an external directory such as OIDC resolves the address through the same index as aliases, so an alias on another account would sign that login in to it), credentials, roles, permissions, name, domain, description, locale, encryption, tenant and anything else; creating and destroying accounts are unchanged. Unchanged too: the `sysAccountUpdate` permission is still required, and group IDs must name existing groups (foreign key to an account of type group). Membership gives a user the groups' data (owner rights on the group accounts) and whatever is shared with the groups (ACLs), not the groups' permissions or roles. SCIM user updates and SCIM group-membership writes (which need SCIM access) go through the same check, so they get the same exemption. A disk quota of 0 means unlimited; the object quotas include API keys and app passwords, which never exceed the account's own permissions. Tests: unit tests of `is_directory_update` (each allowed field, each refused field, mixes, groups, a change of account type), and `sgnl/account-update-probe.py` against a running server in CI, which checks the wiring into the update path (a refused case must fail with `forbidden`, or `invalidForeignKey` for a user given as a group) | `crates/jmap/src/registry/mapping/principal.rs`, `sgnl/account-update-probe.py` (new: checks the rule against a running server, in CI and on a throwaway copy) | 2026-11-26 |
| **Creating groups with the defaults.** Upstream checks on the creation of a group that the caller holds every permission the group would have, i.e. those of the default group roles, so a client with `sysAccountCreate` but without mail permissions can't create a shared mailbox. In this fork the check is skipped when the new group has inherited permissions, the default roles, no aliases and, in the enterprise edition, no tenant and no external ID (`is_plain_group`); its name, domain, description, quotas, locale and time zone are free. Such a group gets nothing every other plain group doesn't have: a group has no credentials, a login through an external directory that resolves to a group is refused (`sync_account`: "does not correspond to a user account"), and membership gives the group's data and what is shared with it, not its permissions or roles. A group's name is an address in the same global unique index as users and aliases, so it can't take an address in use; it can take one no one uses yet, and then mail to that address goes to the group's members, and a later login through an external directory at that address is refused (`sync_account` refuses an address that resolves to a group). If an external directory maps group claims (`claimGroups`), users with a matching group claim become members of a group of that address. SCIM group creation (`group_insert`) goes through the same check, so a SCIM group without an external ID gets the same exemption. `sysAccountCreate` is still required, and creating users, or groups with other settings, still runs the full check. Tests: unit tests of `is_plain_group` (defaults, free fields, permissions, empty replaced permissions, custom roles, aliases, tenant, external ID), and group and user creation cases in `sgnl/account-update-probe.py` | `crates/jmap/src/registry/mapping/principal.rs`, `sgnl/account-update-probe.py` | 2026-11-26 |
| Tests and image build of the fork; upstream's workflows (CI, releases to Docker Hub, scorecard, Trivy, auto-closing of issues, PRs and discussions) and Dependabot config removed | `.github/workflows/sgnl-test.yml` (new), `sgnl/Dockerfile` (new), `.github/workflows/{ci.yml,ci-retry.yml,scorecard.yml,trivy.yml,auto-close-issues.yml,auto-close-prs.yml,auto-redirect-discussions.yml}` (removed), `.github/dependabot.yml` (removed) | 2026-11-26 |
| This file | `FORK.md` (new) | 2026-11-26 |

## Licence

Stalwart is licensed under `AGPL-3.0-only OR LicenseRef-SEL` (see `LICENSES/`). The fork's change is made
under the AGPL-3.0, in code outside the `LicenseRef-SEL` snippets, and is offered under the same terms; the
complete source of every image built from it is this repository at the image's tag. No `LicenseRef-SEL` snippet is
modified. Images are built with upstream's features, which include the `enterprise` feature and so the
`LicenseRef-SEL` code; that code remains under the Stalwart Enterprise License, whose terms (no
redistribution of the software, modifications for internal use only, a licence key for enterprise
functionality) apply to it. For that reason this fork publishes no images or binaries; they are built and
used internally. Without a licence key the server runs as the Community Edition. Copyright
notices and licence headers are kept as they are upstream.

## Upstream

Stalwart accepts pull requests only from vouched contributors, accepts no AI-generated code, and requires a
signed Fiduciary Contributor License Agreement (see `CONTRIBUTING.md` and `AGENTS.md`). This change was not
sent upstream; any proposal goes through [support.stalw.art](https://support.stalw.art) by a person who can
answer for it.
