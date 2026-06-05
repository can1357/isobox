package main

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
)

// version is the release version. It is injected at build time with
// -ldflags "-X main.version=..." (goreleaser does this for tagged builds).
// When empty, versionString derives what it can from the embedded build info,
// so `go build` and `go install` still report a useful value.
var version = ""

// versionString returns the human-readable version. A version injected via
// -ldflags is enriched with the VCS revision, dirty flag, and commit time the
// Go toolchain stamps into the binary. A module pseudo-version already encodes
// those, so it is returned as-is.
func versionString() string {
	if version != "" {
		return version + vcsDetail()
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "(devel)" + vcsDetail()
}

// vcsDetail returns " (revision[, dirty][, time])" from the embedded build
// info, or "" when no VCS stamps are present.
func vcsDetail() string {
	var revision, buildTime string
	var modified bool
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			case "vcs.time":
				buildTime = s.Value
			}
		}
	}
	if revision == "" {
		return ""
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	parts := []string{revision}
	if modified {
		parts = append(parts, "dirty")
	}
	if buildTime != "" {
		parts = append(parts, buildTime)
	}
	return fmt.Sprintf(" (%s)", strings.Join(parts, ", "))
}

// printVersion writes the version banner and the toolchain/platform line.
func printVersion(w io.Writer) {
	fmt.Fprintf(w, "isobox %s\n", versionString())
	fmt.Fprintf(w, "%s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
