# Common development tasks.

isoboxfs_dir := "preload/isoboxfs"
isoboxfs_cppflags := "-DISOBOXFS_VERSION_TEXT='\"0.1.0\"' -Wall -Wextra -fPIC"

# List available recipes.
default:
    @just --list

# Bootstrap dependencies.
init:
    @test -d .git || git init
    go mod download
    go mod tidy

# Install developer tooling (linters and the vulnerability scanner).
tools:
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
    go install golang.org/x/vuln/cmd/govulncheck@latest

# Build the main CLI.
build:
    go build -o isobox ./cmd/isobox

# Run Go tests.
test:
    go test ./...

# Run Go tests with the race detector.
test-race:
    go test -race ./...

# Format Go and C sources in place.
fmt: fmt-c
    gofmt -w .

# Format the C preload sources in place.
fmt-c:
    cd {{isoboxfs_dir}} && clang-format -i *.c *.h

# Fail if any Go or C source is not formatted (used in CI).
fmt-check:
    #!/usr/bin/env bash
    set -euo pipefail
    unformatted="$(gofmt -l .)"
    if [ -n "$unformatted" ]; then
        echo "These files need 'just fmt':" >&2
        echo "$unformatted" >&2
        exit 1
    fi
    cd {{isoboxfs_dir}} && clang-format --dry-run --Werror *.c *.h

# Vet and lint the Go sources for the host GOOS.
lint:
    go vet ./...
    golangci-lint run ./...

# Lint every supported GOOS so platform-specific files are all analyzed.
lint-all:
    GOOS=linux golangci-lint run ./...
    GOOS=darwin golangci-lint run ./...
    GOOS=windows golangci-lint run ./...

# Scan dependencies for known vulnerabilities.
vuln:
    govulncheck ./...

# Tidy and verify the module graph.
tidy:
    go mod tidy
    go mod verify

# Run the local CI subset. The C preload is Linux-only.
ci: build fmt-check lint test vuln
    @if [ "$(uname -s)" = "Linux" ]; then just isoboxfs-test; fi

# Remove generated artifacts.
clean:
    rm -f isobox isobox.exe
    go clean
    just isoboxfs-clean

# Build the Linux C LD_PRELOAD filesystem shim.
isoboxfs-build:
    cd {{isoboxfs_dir}} && cflags="${CFLAGS:--O2 -g}" && ${CC:-cc} ${CPPFLAGS:-} {{isoboxfs_cppflags}} $cflags -c -o isoboxfs.o isoboxfs.c
    cd {{isoboxfs_dir}} && cflags="${CFLAGS:--O2 -g}" && ${CC:-cc} ${CPPFLAGS:-} {{isoboxfs_cppflags}} $cflags -c -o scope.o scope.c
    cd {{isoboxfs_dir}} && ldlibs="${LDLIBS_SO:--ldl -pthread}" && ${CC:-cc} -shared -o libisoboxfs.so isoboxfs.o scope.o $ldlibs

# Build and run the C scope unit test and Linux LD_PRELOAD runtime smoke test.
isoboxfs-test: isoboxfs-build
    cd {{isoboxfs_dir}} && cflags="${CFLAGS:--O2 -g}" && ${CC:-cc} ${CPPFLAGS:-} {{isoboxfs_cppflags}} $cflags -c -o test_scope.o test_scope.c
    cd {{isoboxfs_dir}} && ${CC:-cc} -o test_scope test_scope.o scope.o
    cd {{isoboxfs_dir}} && ./test_scope
    cd {{isoboxfs_dir}} && cflags="${CFLAGS:--O2 -g}" && ${CC:-cc} ${CPPFLAGS:-} {{isoboxfs_cppflags}} $cflags -c -o test_runtime.o test_runtime.c
    cd {{isoboxfs_dir}} && ${CC:-cc} -o test_runtime test_runtime.o
    cd {{isoboxfs_dir}} && ./test_runtime ./libisoboxfs.so

# Remove generated C preload artifacts.
isoboxfs-clean:
    rm -f {{isoboxfs_dir}}/isoboxfs.o {{isoboxfs_dir}}/scope.o {{isoboxfs_dir}}/test_scope.o {{isoboxfs_dir}}/test_runtime.o {{isoboxfs_dir}}/libisoboxfs.so {{isoboxfs_dir}}/test_scope {{isoboxfs_dir}}/test_runtime
