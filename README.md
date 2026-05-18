# Passwork CLI

`passwork-cli` is a cross-platform command-line utility for the Passwork API.

This is an independent third-party CLI project and is not officially affiliated with or endorsed by Passwork.

It supports both Passwork encryption modes in one binary:

- default encryption mode
- client-side encryption (CSE)

Core capabilities:

- fetch and decrypt records (`get`)
- run commands with secrets injected into the child environment (`exec`)
- update records (`update`)
- call raw API endpoints (`api`)
- use crypto helpers compatible with the Passwork format (`crypto`)

## Requirements

- Go `1.25+` for local builds; use the latest patch release of your Go version
- Passwork API URL and access token for API commands

Environment variables:

- `PASSWORK_URL` - Passwork API base URL, for example `https://passwork.example.com`
- `PASSWORK_ACCESS_TOKEN` - API access token
- `PASSWORK_MASTER_KEY` - optional base64 user master key for CSE records

## Install

From source:

```bash
go install github.com/free-spaces/passwork-cli/cmd/passwork-cli@latest
```

For a local checkout:

```bash
go build -o passwork-cli ./cmd/passwork-cli
./passwork-cli --help
```

Tagged releases publish Linux, macOS, and Windows binaries with SHA-256 checksums.

## Global Flags

- `--no-ssl-verify` - disable TLS certificate verification for API calls (`get`, `exec`, `update`, `api`)

Examples:

```bash
passwork-cli --no-ssl-verify api --method GET --endpoint "v1/vaults"
passwork-cli get --password-id "<item-id>" --no-ssl-verify
```

## Commands

| Command | Purpose |
|---|---|
| `get` | Fetch item/shortcut by ID; print JSON or a single field |
| `exec` | Fetch item/shortcut, inject secrets as `pwk_*` env vars, run a child process |
| `update` | Update item/shortcut fields; supports CSE password update |
| `api` | Raw API request mode (`GET`, `POST`, `PATCH`, `DELETE`, `PUT`) |
| `crypto` | Encrypt/decrypt values and keys without API calls |
| `version` | Print CLI version |

## Encryption Modes

Default encryption requires:

- `PASSWORK_URL`
- `PASSWORK_ACCESS_TOKEN`

Client-side encryption (CSE) also requires:

- `PASSWORK_MASTER_KEY`

For CSE, the CLI computes `Passwork-MasterKeyHash`, fetches the encrypted user private key, decrypts it, and uses it for item operations.

## `get`

Fetch an item or shortcut and decode/decrypt fields.

```bash
passwork-cli get --password-id "<item-id>"
passwork-cli get --shortcut-id "<shortcut-id>"
passwork-cli get --password-id "<item-id>" --field password
```

`--field` supports:

- `password`
- `url`
- `login`
- custom field name

## `exec`

Fetch an item or shortcut, inject password values as `pwk_*` environment variables, and run a child process.

```bash
passwork-cli exec --password-id "<item-id>" --cmd "./deploy.sh"
passwork-cli exec --password-id "<item-id>" --cmd "env"
passwork-cli exec --password-id "<item-id>" --cmd "echo \$pwk_pwd" --shell
```

Notes:

- direct mode runs the command without shell expansion
- direct mode can pass exact arguments after `--`, for example `--cmd /bin/echo -- "value with spaces"`
- `--shell` executes through `cmd /C` on Windows or `sh -c` on Unix
- the CLI exits with the child process exit code

## `update`

Update item or shortcut fields:

```bash
passwork-cli update --password-id "<item-id>" --name "New name"
passwork-cli update --password-id "<item-id>" --login "user@example.com" --password "secret"
passwork-cli update --shortcut-id "<shortcut-id>" --tags "tag1,tag2"
```

For CSE records, updating a password requires `PASSWORK_MASTER_KEY`.

## `api`

Raw API mode with method, endpoint, and optional JSON body.

```bash
passwork-cli api --method GET --endpoint "v1/vaults"
passwork-cli api --method POST --endpoint "v1/vaults" --params '{"name":"cli vault"}'
passwork-cli api --method PATCH --endpoint "/api/v1/items/<item-id>" --params '{"name":"updated"}'
```

Accepted endpoint forms:

- `/api/v1/items/...`
- `api/v1/items/...`
- `v1/items/...`
- `items/...`

The CLI normalizes API endpoints to `/api/v1/...` when needed. `--method` is case-insensitive.

## `crypto`

Crypto helpers in Passwork-compatible format.

```bash
passwork-cli crypto enc --value "secret" --key "master"
passwork-cli crypto dec "<ciphertext>" --key "<master>"
passwork-cli crypto dec-mk "<vaultMasterKeyEncrypted>" -key-file user_private.pem
passwork-cli crypto enc-mk "<vaultMasterKey>" -key-file user_public.pem
passwork-cli crypto gen-rsa -key "$PASSWORK_MASTER_KEY"
```

Also supported:

- `passwork-cli crypto dec "<ciphertext>" "<key>"` (positional fallback)

## Typical Profiles

Default mode:

```bash
export PASSWORK_ACCESS_TOKEN="<access-token>"
export PASSWORK_URL="https://passwork.example.com"
unset PASSWORK_MASTER_KEY
```

CSE mode:

```bash
export PASSWORK_ACCESS_TOKEN="<access-token>"
export PASSWORK_MASTER_KEY="<base64-master-key>"
export PASSWORK_URL="https://passwork.example.com"
```

## Kubernetes

Ready-to-adapt Kubernetes templates are in `examples/k8s/`.

## Development

Run local checks:

```bash
gofmt -w cmd
go test ./...
go vet ./...
```

If available, also run:

```bash
govulncheck ./...
```

Cross-platform build examples:

```bash
GOOS=linux GOARCH=amd64 go build -o passwork-cli-linux-amd64 ./cmd/passwork-cli
GOOS=darwin GOARCH=arm64 go build -o passwork-cli-darwin-arm64 ./cmd/passwork-cli
GOOS=windows GOARCH=amd64 go build -o passwork-cli-windows-amd64.exe ./cmd/passwork-cli
```

## Security Notes

- `--no-ssl-verify` weakens transport security; use only in controlled environments.
- `exec` passes secrets via child environment variables; avoid logging child environments.
- Keep `PASSWORK_ACCESS_TOKEN` and `PASSWORK_MASTER_KEY` out of shell history and CI logs.
- Prefer least-privileged API tokens for automation.
- Crypto helpers exist for compatibility with Passwork data formats; they are not a recommendation for new application cryptography.

## License

MIT