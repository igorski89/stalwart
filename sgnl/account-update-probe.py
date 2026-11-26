#!/usr/bin/env python3
"""Checks the fork's account update rule against a running Stalwart (a throwaway copy, never production).

Usage: [AUTH=password|impersonate] account-update-probe.py BASE_URL < admin-credentials
       (stdin, first line: an administrator's "user:password", e.g. the recovery admin)

AUTH=password (default, for an empty server): the test accounts get passwords and probe logs in with its
own. AUTH=impersonate (for a server whose domains use an external directory such as OIDC, where passwords
can't be set): the accounts get no credentials, and probe's calls log in as "probe@domain%<admin user>"
with the administrator's password. The recovery admin's impersonation yields the impersonated account's
own access token (crates/common/src/auth/authentication.rs, authenticate_basic: `self.access_token(account_id)`
for the impersonated account), so the calls run with probe's permissions, not the administrator's.

As the administrator it creates its own accounts: two groups, a user, and "probe", a user whose
permissions are replaced with authenticate, sysAccountGet, sysAccountQuery and sysAccountUpdate (like an
automated directory client). As probe it then updates the user and a group. The fork allows changes of
memberGroupIds, aliases and quotas only; upstream refuses all of them, because probe doesn't hold every
permission of the user. At the end it reads the accounts back as the administrator and destroys what it
created. Prints one line per case (PASS/FAIL), never a credential. Exit code 0 when every case passes.
Python 3 standard library only.
"""

import base64
import os
import json
import secrets
import sys
import urllib.error
import urllib.request

CAPS = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]


class Client:
    def __init__(self, base, user, password):
        self.base = base.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}", "Content-Type": "application/json"}
        session = self.request("GET", "/jmap/session")
        self.account = session["primaryAccounts"]["urn:stalwart:jmap"]

    def request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as err:
            raise SystemExit(f"{method} {path}: HTTP {err.code}") from None

    def call(self, name, args):
        args = {"accountId": self.account, **args}
        resp = self.request("POST", "/jmap/", {"using": CAPS, "methodCalls": [[name, args, "0"]]})
        result_name, result, _ = resp["methodResponses"][0]
        if result_name == "error":
            raise SystemExit(f"{name}: {result.get('type')} {result.get('description', '')}")
        return result

    def create(self, obj, value):
        result = self.call(f"x:{obj}/set", {"create": {"new": value}})
        if "new" not in result.get("created", {}):
            reason = result.get("notCreated", {}).get("new", {})
            raise SystemExit(f"setup: could not create {obj}: {reason.get('type')} {reason.get('description', '')}")
        return result["created"]["new"]["id"]

    def update(self, obj, oid, patch):
        """Returns None when updated, else the error (type and description)."""
        result = self.call(f"x:{obj}/set", {"update": {oid: patch}})
        if oid in result.get("updated", {}) or oid in (result.get("updated") or {}):
            return None
        err = result.get("notUpdated", {}).get(oid, {"type": "unknown"})
        return f"{err.get('type')}: {(err.get('description') or '')[:60]}".strip()

    def get(self, obj, oid):
        result = self.call(f"x:{obj}/get", {"ids": [oid]})
        return result["list"][0] if result.get("list") else None

    def destroy(self, obj, oids):
        if oids:
            self.call(f"x:{obj}/set", {"destroy": oids})


def password():
    return "Pr0be-" + secrets.token_urlsafe(24)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    base = sys.argv[1]
    admin_user, _, admin_password = sys.stdin.readline().rstrip("\n").partition(":")
    if not admin_password:
        raise SystemExit("stdin: expected user:password on the first line")
    auth = os.environ.get("AUTH", "password")
    if auth not in ("password", "impersonate"):
        raise SystemExit("AUTH must be password or impersonate")
    impersonate = auth == "impersonate"
    admin = Client(base, admin_user, admin_password)

    domains = admin.call("x:Domain/query", {}).get("ids", [])
    created_domain = None
    if domains:
        domain_id = domains[0]
    else:  # an empty server (local test): make a domain for the test accounts
        created_domain = domain_id = admin.create("Domain", {"name": "probe.test"})
    domain_name = admin.get("Domain", domain_id)["name"]

    tag = secrets.token_hex(3)
    accounts = []
    group_a = admin.create("Account", {"@type": "Group", "name": f"probe-group-a-{tag}", "domainId": domain_id})
    accounts.append(group_a)
    group_b = admin.create("Account", {"@type": "Group", "name": f"probe-group-b-{tag}", "domainId": domain_id})
    accounts.append(group_b)
    user_password = password()
    user = admin.create("Account", {
        "@type": "User", "name": f"probe-user-{tag}", "domainId": domain_id,
        **({} if impersonate else {"credentials": {"0": {"@type": "Password", "secret": user_password}}}),
    })
    accounts.append(user)
    probe_name = f"probe-{tag}"
    probe_password = password()
    probe = admin.create("Account", {
        "@type": "User", "name": probe_name, "domainId": domain_id,
        **({} if impersonate else {"credentials": {"0": {"@type": "Password", "secret": probe_password}}}),
        "permissions": {"@type": "Replace", "disabledPermissions": {}, "enabledPermissions": {
            "authenticate": True, "sysAccountGet": True, "sysAccountQuery": True, "sysAccountUpdate": True}},
    })
    accounts.append(probe)

    failures = 0

    def case(name, error, expect_allowed):
        nonlocal failures
        ok = (error is None) == expect_allowed
        failures += not ok
        expected = "allowed" if expect_allowed else "refused"
        got = "allowed" if error is None else f"refused ({error})"
        print(f"{'PASS' if ok else 'FAIL'}  {name}: expected {expected}, {got}")

    try:
        if impersonate:
            as_probe = Client(base, f"{probe_name}@{domain_name}%{admin_user}", admin_password)
        else:
            as_probe = Client(base, f"{probe_name}@{domain_name}", probe_password)
        print(f"auth: {auth}; probe acts as account {as_probe.account}, the administrator as {admin.account}")
        if as_probe.account == admin.account:
            raise SystemExit("probe's calls run as the administrator: the test would prove nothing")

        before = admin.get("Account", user)
        alias = {"0": {"enable": True, "name": f"probe-alias-{tag}", "domainId": domain_id}}

        # The fork allows these (upstream refuses them).
        case("user: add to a group (memberGroupIds)",
             as_probe.update("Account", user, {"memberGroupIds": {group_a: True}}), True)
        case("user: change groups (memberGroupIds)",
             as_probe.update("Account", user, {"memberGroupIds": {group_b: True}}), True)
        case("user: remove from all groups (memberGroupIds)",
             as_probe.update("Account", user, {"memberGroupIds": {}}), True)
        case("user: add an alias", as_probe.update("Account", user, {"aliases": alias}), True)
        case("user: set a disk quota", as_probe.update("Account", user, {"quotas": {"maxDiskQuota": 1 << 30}}), True)
        case("group: set a disk quota", as_probe.update("Account", group_a, {"quotas": {"maxDiskQuota": 1 << 30}}), True)

        # Still refused.
        case("user: change the password", as_probe.update("Account", user, {
            "credentials": {"0": {"@type": "Password", "secret": password()}}}), False)
        case("user: change permissions", as_probe.update("Account", user, {
            "permissions": {"@type": "Merge", "disabledPermissions": {},
                            "enabledPermissions": {"impersonate": True}}}), False)
        case("user: make administrator (roles)", as_probe.update("Account", user, {"roles": {"@type": "Admin"}}), False)
        case("user: change the description (control)",
             as_probe.update("Account", user, {"description": "changed by probe"}), False)
        case("user: group change together with a description change", as_probe.update("Account", user, {
            "memberGroupIds": {group_a: True}, "description": "changed by probe"}), False)
        case("user: a user as a group (memberGroupIds)",
             as_probe.update("Account", user, {"memberGroupIds": {probe: True}}), False)
        case("group: add an alias", as_probe.update("Account", group_a, {"aliases": {
            "0": {"enable": True, "name": f"probe-group-alias-{tag}", "domainId": domain_id}}}), False)
        case("group: change permissions", as_probe.update("Account", group_a, {
            "permissions": {"@type": "Merge", "disabledPermissions": {},
                            "enabledPermissions": {"impersonate": True}}}), False)

        # What the server kept.
        after = admin.get("Account", user)
        kept = (after.get("memberGroupIds") or {}) == {} and bool(after.get("aliases")) \
            and (after.get("quotas") or {}).get("maxDiskQuota") == 1 << 30
        unchanged = all(after.get(p) == before.get(p) for p in ("credentials", "permissions", "roles", "description"))
        case("user: the allowed changes were stored, nothing else changed", None if kept and unchanged else
             f"stored groups/aliases/quota {kept}, other fields unchanged {unchanged}", True)
        if not impersonate:
            login = True
            try:
                Client(base, f"probe-user-{tag}@{domain_name}", user_password)
            except SystemExit:
                login = False
            case("user: the old password still works", None if login else "login failed", True)
    finally:
        admin.destroy("Account", list(reversed(accounts)))
        if created_domain:
            admin.destroy("Domain", [created_domain])

    print(f"{'ALL PASS' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
