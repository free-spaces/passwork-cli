# Contributing

Thanks for helping improve `passwork-cli`.

## Development

Requirements:

- Go 1.25 or newer, using the latest patch release available

Run the local checks before opening a pull request:

```bash
gofmt -w cmd
go test ./...
go vet ./...
```

If `govulncheck` is installed, also run:

```bash
govulncheck ./...
```

## Pull Requests

- Keep changes focused and easy to review.
- Add or update tests for behavioral changes.
- Do not include real Passwork URLs, tokens, master keys, item IDs, shortcut IDs, or decrypted secrets.
- Prefer clear, idiomatic Go over clever abstractions.

## Releases

Releases are built from Git tags. Maintainers should tag versions as `vX.Y.Z`; the release workflow builds cross-platform binaries and checksum files.
