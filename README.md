# vault-plugin-secrets-auth0

[![CI](https://github.com/Believe-SA/vault-plugin-secrets-auth0/actions/workflows/ci.yml/badge.svg)](https://github.com/Believe-SA/vault-plugin-secrets-auth0/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Believe-SA/vault-plugin-secrets-auth0)](https://github.com/Believe-SA/vault-plugin-secrets-auth0/releases/latest)

Vault secrets engine for Auth0, multi-tenant on a single mount. Each read of a role creates a new M2M client (application) with the role's grants, and returns its client ID and secret under a Vault lease. The client is deleted when the lease expires or is revoked, replacing long-lived client credentials with short-lived ones.

Every read creates a different client: the client ID (the token's **azp**) changes each time. Client metadata set on the role (e.g. **ratelimit_tier**) is copied to every created client.

Tested against Vault 1.21 and 2.x.

## Install a pre-built binary

Releases ship the raw plugin binary for linux and darwin (amd64, arm64) and a **checksums.txt**. Download the asset matching the Vault server, verify it, and copy it to the Vault **plugin_directory** under the name **vault-plugin-secrets-auth0** (on every Vault node):

```shell
VERSION=0.1.0
BASE=https://github.com/Believe-SA/vault-plugin-secrets-auth0/releases/download/v$VERSION
http --download --output vault-plugin-secrets-auth0 $BASE/vault-plugin-secrets-auth0_${VERSION}_linux_amd64
http --download $BASE/checksums.txt
grep "_${VERSION}_linux_amd64$" checksums.txt   # compare with the next line
sha256sum vault-plugin-secrets-auth0
```

Register the SHA-256 and the version (the binary reports its version, Vault refuses a mismatch), pin it and mount the engine:

```shell
vault plugin register -sha256=<sha256> -version=$VERSION \
  -command=vault-plugin-secrets-auth0 secret auth0
vault write sys/plugins/pins/secret/auth0 version=$VERSION
vault secrets enable -path=auth0 auth0
```

To upgrade, copy the new binary, register the new version, update the pin and reload: **vault plugin reload -plugin=auth0**.

## Build from source

Requires Go (see **go.mod**):

```shell
make build                  # bin/vault-plugin-secrets-auth0 for the local OS/arch
make dist VERSION=0.1.0     # static linux amd64/arm64 binaries and SHA256SUMS in dist/
```

## Auth0 prerequisites

Each tenant needs an M2M client authorized on the Management API with the scopes **create:clients**, **delete:clients** and **create:client_grants**.

## Paths

| Path | Operations | Description |
|---|---|---|
| **tenants/** | list | Configured tenants |
| **<tenant>/config** | write, read, delete | Tenant domain and Management API client (secret is write-only) |
| **<tenant>/roles/<name>** | write, read, list, delete | Grants and lease TTLs of the dynamic clients |
| **<tenant>/creds/<role>** | read | New dynamic client (leased) |

**tenants** is a reserved tenant name. A tenant can't be deleted while it still has roles.

## Usage

```shell
vault write auth0/example/config \
  domain=example.eu.auth0.com client_id=<mgmt client id> client_secret=<mgmt client secret>

vault write auth0/example/roles/ci ttl=1h max_ttl=24h \
  grants="https://api.example.com=read:orders write:orders" \
  client_metadata="ratelimit_tier=gold"
vault read auth0/example/creds/ci
```

Role fields:

| Field | Description |
|---|---|
| **grants** | Required. Audience to space-separated scopes, one client grant per audience |
| **client_metadata** | Metadata set on the created clients, e.g. **ratelimit_tier** |
| **name_template** | Name of the created clients, see [Client names](#client-names) |
| **ttl**, **max_ttl** | Lease TTLs (seconds or durations), mount defaults when unset |

Policies can target one tenant, e.g. **auth0/prod/*** or **auth0/+/creds/ci**.

## Client names

The created client name comes from the role **name_template**, same syntax and functions as the database engines' **username_template**, with **.RoleName** and **.DisplayName** (the requesting token's display name, which Vault prefixes with the auth mount path, e.g. **oidc-john.doe@example.com** for a human logged in through an **oidc/** mount, **kubernetes-...** for a workload logged in through a **kubernetes/** mount). Default: **vault-<role>-<8 random chars>**.

```shell
vault write auth0/example/roles/ci grants="https://api.example.com=read:orders" \
  name_template='{{ if eq (.DisplayName | truncate 11) "kubernetes-" }}{{ printf "vault-kube-%s-%s" .RoleName (random 4) }}{{ else }}{{ printf "vault-%s-%s-%s" .RoleName (.DisplayName | replace "oidc-" "" | replace "@example.com" "") (random 4) }}{{ end }}'
```

The client description also records the display name: **Managed by Vault role <tenant>/<role> for <display name>**.

## Lifetimes

- **Client credentials**: the Vault lease, set by the role **ttl**/**max_ttl** (mount defaults when unset). Renewal extends it up to **max_ttl**.
- **Access tokens** obtained with them: the **token_lifetime** of the Auth0 API (86400s by default). Tokens are JWTs and stay valid after the client is deleted, until they expire.

## Managing leases

Each dynamic client is tied to a Vault lease. Listing them goes through **sys/leases/lookup/** with the creds path as prefix, and needs the **sudo** capability on **sys/leases/lookup/***:

```shell
# Roles with active leases in a tenant
vault list sys/leases/lookup/auth0/example/creds/

# Leases of one role, and the details of one (expire time, TTL)
vault list sys/leases/lookup/auth0/example/creds/ci/
vault lease lookup auth0/example/creds/ci/<lease id>
```

Revoking a lease deletes its Auth0 client:

```shell
vault lease revoke auth0/example/creds/ci/<lease id>   # one lease
vault lease revoke -prefix auth0/example/creds/ci      # every lease of a role
vault lease revoke -prefix auth0/example/creds             # every lease of a tenant
vault lease revoke -sync -prefix auth0/                    # the whole mount, waiting for the deletions
```

Avoid **-force**: it drops the leases from Vault even when the clients can't be deleted, leaving them in Auth0.

## Development

| Command | Description |
|---|---|
| **make test** | Unit tests against a fake Auth0 (race detector) |
| **make lint** | golangci-lint (same version as CI: v2.14.0) |
| **make test-vault** | Integration tests in a real Vault dev server (Docker): catalog registration with sha256 and version, pinned mount, plugin reload, every path. **VAULT_VERSION** picks the Vault image (default 2.1.1) |
| **make up** / **make down** | Dev Vault in Docker with the plugin mounted at **auth0/** |
| **make dev** / **make enable** | Same without Docker, with the local **vault** binary |

The Makefile targets always talk to the local dev Vault (**http://127.0.0.1:8200**), whatever **VAULT_ADDR** is set in the shell.

CI (GitHub Actions) runs formatting, **go mod tidy**, vet, unit tests, lint, cross-builds and **make test-vault** on Vault 1.21, 2.0, 2.1 and latest. govulncheck, CodeQL and Semgrep run on **main** and pull requests, Dependabot updates Go modules and actions.

### Local testing with Docker

Requires Docker with Compose and the **vault** CLI on the host. **make up** builds a static Linux binary into **bin/linux/**, starts a dev Vault (**hashicorp/vault:2.1.1** by default) with it as plugin directory, and mounts the plugin at **auth0/**. Dev mode registers the plugins of that directory itself.

```shell
make up
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
vault secrets list
```

Use another Vault version with **VAULT_VERSION=2.2.1 make up**. After a code change, run **make down up** to rebuild and remount.

Against a real tenant, preferably a test one, use a Management API M2M client with the scopes listed above:

```shell
vault write auth0/test/config domain=example-test.eu.auth0.com \
  client_id=<mgmt client id> client_secret=<mgmt client secret>
vault write auth0/test/roles/ci ttl=5m max_ttl=1h \
  grants="<api identifier>=<scope> <scope>"
vault read auth0/test/creds/ci     # client appears in Auth0 > Applications

http --form POST https://example-test.eu.auth0.com/oauth/token \
  grant_type=client_credentials client_id=<client_id> client_secret=<client_secret> \
  audience=<api identifier>

vault lease revoke -prefix auth0/test/creds/ci   # client is deleted
```

Stop and discard everything (dev mode keeps no data) with **make down**. Revoke the leases first, otherwise their clients stay in Auth0.

### Without Docker

```shell
make dev      # dev Vault on 127.0.0.1:8200 with ./bin as plugin directory
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
make enable   # in another shell: register and mount the plugin at auth0/
```

Both use port 8200, so run one at a time.

## Releasing

Releases are cut by GitHub Actions (**.github/workflows/release.yml**) with GoReleaser, after the full CI passes:

- **Push to main**: the next version is derived from the Conventional Commits since the last tag (**feat:** minor, **fix:** patch, **!** major); docs/chore/ci-only pushes produce no release
- **Push a v* tag**: releases that exact version

The version is stamped in the binary (**-X ...Version**) and reported to Vault, so registrations must use the release version.

## License

Apache License 2.0, see [LICENSE](LICENSE).
