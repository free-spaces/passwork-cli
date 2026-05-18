# Security Policy

## Reporting a Vulnerability

Please do not open public issues for suspected vulnerabilities.

Report security issues by emailing the project maintainers or by using GitHub's private vulnerability reporting if it is enabled for this repository.

Include:

- affected version or commit
- steps to reproduce
- expected and observed behavior
- any relevant logs with secrets redacted

## Secret Handling

`passwork-cli` works with credentials, API tokens, and decrypted secret values. Avoid posting command output, environment dumps, Kubernetes manifests, or CI logs that contain:

- `PASSWORK_ACCESS_TOKEN`
- `PASSWORK_MASTER_KEY`
- decrypted `pwk_*` environment variables
- Passwork item or shortcut identifiers from private vaults

## Transport Security

The `--no-ssl-verify` flag disables TLS certificate verification. Use it only in controlled environments where the network and endpoint identity are otherwise trusted.
