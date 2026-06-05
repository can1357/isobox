package isobox

import (
	"os"
	"os/exec"
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

// resolveExec resolves a command to an absolute, symlink-free path, using PATH
// when it is a bare name. ok is false when the executable cannot be located.
func resolveExec(cmd string) (path string, ok bool) {
	if cmd == "" {
		return "", false
	}
	if strings.ContainsRune(cmd, filepath.Separator) {
		return canonPath(cmd), true
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
