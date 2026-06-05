# Contributing to isobox

Thanks for taking the time to help. This document covers the setup and the
checks your change needs to pass.

## Prerequisites

- Go 1.26 or newer (`go.mod` pins the minimum).
- [`just`](https://github.com/casey/just) for the task recipes.
- A C compiler (`cc`/`gcc`/`clang`) if you touch the Linux preload under
  `preload/isoboxfs`.
- The developer tools, installed once with `just tools`:
  - `golangci-lint` v2.12.2
  - `govulncheck`
- `clang-format` 20.1.7 for the C preload (`pipx install clang-format==20.1.7`,
  or your distro package). The `.clang-format` style is stable across recent
  versions.

## Everyday commands

```sh
just build        # build the CLI
just test         # run the Go test suite
just test-race    # run the suite under the race detector
just fmt          # format Go and C sources in place
just fmt-check    # fail if anything is unformatted (what CI runs)
just lint         # vet + golangci-lint for your host GOOS
just lint-all     # golangci-lint for linux, darwin, and windows
just vuln         # govulncheck
just ci           # build + fmt-check + lint + test + vuln (+ C preload on Linux)
```

Run `just ci` before opening a pull request. On non-Linux hosts it skips the C
preload build and tests; those run on Linux in GitHub Actions.

## Cross-platform code

isobox compiles on Linux, macOS, and Windows, and each backend lives behind
build constraints (`//go:build` tags or GOOS filename suffixes). Two
consequences:

- `just lint-all` lints all three GOOS, because a single-GOOS run never sees the
  files for the other platforms. Add the corresponding lint run for any new
  platform-specific file.
- `unused` cannot resolve symbols across build tags. The cross-platform
  scaffolding in `linux_view.go` and `cow_linux_runtime_unsupported.go` is
  excluded from that linter in `.golangci.yml`; keep genuinely dead code out of
  the rest of the tree.

## Tests

- Put tests next to the code (`*_test.go`).
- Assert observable behavior, not internal plumbing or default values.
- The compiler/plan paths are inspectable from any host, so most logic can be
  tested without the backend tool installed (see the existing `*_test.go`
  files). Runtime enforcement for gVisor, AppContainer, and Docker still needs a
  real host; note in the PR what you verified and where. The Windows
  AppContainer end-to-end test is opt-in: run it on a dedicated Windows machine
  with `ISOBOX_WINDOWS_E2E=1`.

## Commits and pull requests

- Keep commits focused and write a clear subject line.
- Describe what you changed and how you verified it.
- CI must be green: tests on all three OSes, the race detector, lint, format,
  `go mod tidy`, govulncheck, and the C preload build and tests.

## Releasing

Releases are cut by pushing a semver tag (`vX.Y.Z`). The release workflow runs
[GoReleaser](https://goreleaser.com), which cross-compiles the `isobox` CLI for
linux/darwin/windows on amd64/arm64, stamps the version via `-ldflags`, and
publishes archives and checksums to the GitHub release. Validate config changes
with `goreleaser check`.

## Security

Do not file security issues in the public tracker. See [SECURITY.md](SECURITY.md).
