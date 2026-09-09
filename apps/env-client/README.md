# keevault bootstrap client

The Go client waits for a human-approved environment, decrypts its secrets, and
launches your application. The launch command must come from the `command`
array in `keevault.json`, or a JSON file selected with `--config`. Run `keevault`
without a trailing command. Positional command arguments and the `--` separator
are rejected. Credentials continue to come from `VAULT_BOOTSTRAP_TOKEN` or its
supported flags.

User documentation lives in the marketing app:

- [Client configuration and usage](../keevault-marketing/content/docs/client.mdx)
- [Getting started](../keevault-marketing/content/docs/getting-started.mdx)
- [Publishing releases](../../docs/releases.md)

## Building

Run from `apps/env-client` with Go 1.26 or newer:

```bash
./build.sh
```

This writes static `linux/amd64` and `linux/arm64` binaries to `dist/` with
`CGO_ENABLED=0 -trimpath -ldflags "-s -w"` and fails if a binary exceeds
15 MiB. The script prints each binary's measured size.

## Tests

```bash
go test ./...
```

The suite covers the crypto primitives with tamper cases, the protocol
decoder, the shared vectors in `crypto/test-vectors` at the repository root
which are skipped when that directory is missing, and a fake vault server that walks a
full approval including a dropped connection, a resume proof, envelope
delivery and the acknowledgement digest.
