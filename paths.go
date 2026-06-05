package isobox

import (
	"os"
	"os/exec"
	slashpath "path"
	"path/filepath"
	"runtime"
	"strings"
)

// firmlinks maps the well-known macOS symlinks to their real /private targets,
// used when a path does not yet exist on disk so EvalSymlinks cannot resolve it.
var firmlinks = []struct{ from, to string }{
	{"/tmp", "/private/tmp"},
	{"/var", "/private/var"},
	{"/etc", "/private/etc"},
}

// canonPath returns an absolute, symlink-resolved path suitable for matching in
// a sandbox policy. macOS resolves /tmp, /var and /etc under /private.
func canonPath(p string) string {
	if p == "" {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	for _, fl := range firmlinks {
		if abs == fl.from || strings.HasPrefix(abs, fl.from+"/") {
			return filepath.Clean(fl.to + strings.TrimPrefix(abs, fl.from))
		}
	}
	return filepath.Clean(abs)
}

// hasPathSyntax reports whether cmd is already a path (absolute or relative)
// instead of a bare executable name. It checks both slash styles so a Linux or
// macOS path remains explicit even when the current host is Windows, and vice
// versa when previewing a Windows backend from a Unix host.
func hasPathSyntax(cmd string) bool {
	return strings.ContainsRune(cmd, '/') || strings.ContainsRune(cmd, '\\')
}

// cleanExplicitPath lexically normalizes an explicit path without rewriting it
// to the current host's path semantics. Forward-slash paths stay forward-slash
// (for Linux/Seatbelt preview from Windows); backslash paths stay backslash
// (for AppContainer preview from Unix hosts).
func cleanExplicitPath(cmd string) string {
	if strings.ContainsRune(cmd, '\\') {
		return strings.ReplaceAll(slashpath.Clean(strings.ReplaceAll(cmd, `\`, "/")), "/", `\`)
	}
	return slashpath.Clean(cmd)
}

// resolveExec resolves a command to an absolute, symlink-free path when the
// executable exists on the current host. For explicit paths that do not exist
// locally, it still returns a lexically cleaned path so backend plans remain
// inspectable from any host.
func resolveExec(cmd string) (resolved string, ok bool) {
	if cmd == "" {
		return "", false
	}
	if hasPathSyntax(cmd) {
		if _, err := os.Lstat(cmd); err == nil {
			return canonPath(cmd), true
		}
		return cleanExplicitPath(cmd), true
	}
	if p, err := exec.LookPath(cmd); err == nil {
		return canonPath(p), true
	}
	return "", false
}

// osTempRoots returns canonical temp roots to grant when AllowTemp is set.
func osTempRoots() []string {
	if runtime.GOOS == "windows" {
		roots := []string(nil)
		for _, name := range []string{"TMP", "TEMP"} {
			if t := os.Getenv(name); t != "" {
				roots = appendGrant(roots, canonPath(t))
			}
		}
		if len(roots) == 0 {
			roots = append(roots, canonPath(os.TempDir()))
		}
		return roots
	}

	if runtime.GOOS == "darwin" {
		roots := []string{"/private/tmp", "/private/var/folders"}
		if t := os.Getenv("TMPDIR"); t != "" {
			roots = appendGrant(roots, canonPath(t))
		}
		return roots
	}

	roots := []string(nil)
	if t := os.Getenv("TMPDIR"); t != "" {
		roots = appendGrant(roots, canonPath(t))
	}
	roots = appendGrant(roots, canonPath(os.TempDir()))
	roots = appendGrant(roots, canonPath("/tmp"))
	return roots
}
