# igorski89/stalwart fork

A fork of [stalwartlabs/stalwart](https://github.com/stalwartlabs/stalwart) with one change to account
updates, for a self-hosted deployment managed by an automated directory client. **Not affiliated with or
endorsed by Stalwart Labs.** For Stalwart itself, use upstream; don't report problems with this fork there.

- Branch `sgnl`, based on upstream tag `v1.1.1` (`3adead91`). Upstream isn't tracked: a new upstream
  release is merged only when needed.
- CI: `.github/workflows/sgnl-test.yml` runs the unit tests of the change. It builds no image and uploads
  no binary.
- Images are built privately and not published: `sgnl/Dockerfile` (target `gnu`, build argument
  `TARGET=x86_64-unknown-linux-gnu`) from a tag `v<upstream version>-sgnl.<n>` (for example
  `v1.1.1-sgnl.1`). It is upstream's `Dockerfile.build` without the FoundationDB binary, the musl stage and
  sccache; the builder runs on the build platform and cross-compiles with zig, as upstream's release does.
  The build features (`sqlite postgres mysql rocks s3 redis keep azure nats enterprise`) and the gnu runtime
  stage (Debian trixie-slim, user `stalwart` 2000:2000, `/etc/stalwart`, `/var/lib/stalwart`, entrypoint
  `/usr/local/bin/stalwart --config /etc/stalwart/config.json`) are upstream's, so the image replaces
  `stalwartlabs/stalwart:v1.1.1`.

## Changes from upstream

Every file this fork modifies, adds or removes, with the date of the change (AGPL-3.0 Section 5(a)).

| Change | Files | Date |
|---|---|---|
| **Account updates that only change group memberships, aliases or quotas.** Upstream checks on every update of an account (JMAP `x:Account/set`, SCIM) that the caller holds every permission of the account being updated, so a client with `sysAccountUpdate` but fewer permissions than a user can't change that user's groups, aliases or quotas. In this fork the check is skipped when the update changes nothing but `memberGroupIds`, `aliases` and `quotas` of a user, or `quotas` of a group (`is_directory_update`: the new account with those fields set back to their old values must equal the old account). Any other change, to credentials, roles, permissions, name, domain, description, locale, encryption, tenant or anything else, alone or with an allowed change, still runs the full check, as do creating and destroying accounts. Unchanged: the `sysAccountUpdate` permission is still required, group IDs must name existing groups (foreign key to an account of type group), aliases must be free (globally unique), and memberships only give access to the groups' own data (`member_of`), not their permissions or roles. Consequences to be aware of: such a client can remove an alias from any account, including an administrator's, and give it to another account; can claim any free address; and can set any quota, including a disk quota of 0 (unlimited). Unit tests: `is_directory_update` for each allowed field, each refused field, a mix, groups, and a change of account type | `crates/jmap/src/registry/mapping/principal.rs`, `sgnl/account-update-probe.py` (new: checks the rule against a running server, for a throwaway copy) | 2026-11-26 |
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
