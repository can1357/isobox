package isobox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func prepareLinuxNamespaceView(fs *fsVirtualizationPlan, plan *Plan, s Spec) (*fsVirtualizationRuntime, error) {
	if fs == nil {
		return nil, fmt.Errorf("isobox: missing linux filesystem view plan")
	}
	return prepareLinuxNamespaceViewRuntime(fs, plan, s, buildLinuxNamespaceView(fs))
}

// prepareLinuxPreloadFallback materializes the LD_PRELOAD fallback selected by
// ISOBOX_PRELOAD_FALLBACK=1 in compileGvisor: it locates the isoboxfs preload
// library, writes the per-launch readable/writable manifests under a temp
// directory, and emits the env contract the preload library (preload/isoboxfs)
// reads — LD_PRELOAD, ISOBOXFS_MODE, ISOBOXFS_READABLE, ISOBOXFS_READ_DENY,
// ISOBOXFS_WRITABLE, and optional ISOBOXFS_UPPER for ephemeral overlay writes.
//
// The libisoboxfs.so payload is built from the C sources under preload/isoboxfs;
// packaging owns staging it beside the isobox binary or in a standard library path.
// On Linux, preparation smoke-tests the selected library before launching the target.
func prepareLinuxPreloadFallback(fs *fsVirtualizationPlan, _ *Plan, s Spec) (*fsVirtualizationRuntime, error) {
	if fs == nil {
		return nil, fmt.Errorf("isobox: missing linux preload fallback plan")
	}

	lib, err := linuxPreloadLocateLibisoboxfs(os.Getenv)
	if err != nil {
		return nil, err
	}

	if err := linuxPreloadSmokeTest(lib); err != nil {
		return nil, err
	}

	tempDir, err := os.MkdirTemp(os.TempDir(), "isobox-preload-")
	if err != nil {
		return nil, fmt.Errorf("isobox: preparing preload fallback temp dir: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(tempDir) }

	readableManifest := filepath.Join(tempDir, "readable.manifest")
	readDenyManifest := filepath.Join(tempDir, "read-deny.manifest")
	writableManifest := filepath.Join(tempDir, "writable.manifest")
	if err := os.WriteFile(readableManifest, linuxPreloadManifestBytes(linuxPreloadReadablePaths(s, fs)), 0o600); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("isobox: writing preload readable manifest: %w", err)
	}
	if err := os.WriteFile(readDenyManifest, linuxPreloadManifestBytes(fs.ReadDeny), 0o600); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("isobox: writing preload read-deny manifest: %w", err)
	}
	if err := os.WriteFile(writableManifest, linuxPreloadManifestBytes(linuxPreloadWritablePaths(fs)), 0o600); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("isobox: writing preload writable manifest: %w", err)
	}

	upper := ""
	if s.Write == WriteEphemeral || s.Write == WriteOverlay {
		upper = filepath.Join(tempDir, "upper")
		if err := os.MkdirAll(upper, 0o700); err != nil {
			_ = cleanup()
			return nil, fmt.Errorf("isobox: preparing preload ephemeral upper dir: %w", err)
		}
	}
	env := linuxPreloadEnv(lib, s, fs, readableManifest, readDenyManifest, writableManifest, upper)

	return &fsVirtualizationRuntime{
		Env:     env,
		Cleanup: cleanup,
		Caveats: []string{"linux LD_PRELOAD filesystem virtualization is best-effort; secure-exec/setuid binaries can ignore it, static binaries and direct syscalls can bypass wrappers, pre-opened descriptors remain usable, and directory enumeration or loader paths not wrapped by libisoboxfs may leak host state"},
	}, nil
}

// linuxPreloadManifestBytes renders an LD_PRELOAD manifest as libisoboxfs
// parses it: one absolute path per line, terminated by '\n', no trailing
// whitespace. Empty input yields a nil slice so an empty file is written.
func linuxPreloadManifestBytes(paths []string) []byte {
	if len(paths) == 0 {
		return nil
	}
	var b strings.Builder
	for _, p := range paths {
		b.WriteString(p)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// linuxPreloadReadablePaths is the explicit readable allowlist plus the minimum
// host paths libisoboxfs must whitelist so the target binary and the dynamic
// linker can resolve their dependencies. Empty explicit readable scope
// deliberately returns nil: libisoboxfs treats an empty manifest as broad
// read access.
func linuxPreloadReadablePaths(s Spec, fs *fsVirtualizationPlan) []string {
	if len(fs.Readable) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(fs.Readable)+8)
	out := make([]string, 0, len(fs.Readable)+8)
	add := func(p string) {
		if p == "" {
			return
		}
		clean := canonPath(p)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	for _, p := range fs.Readable {
		add(p)
	}
	for _, p := range linuxPreloadSystemPaths(s) {
		add(p)
	}
	return out
}

func linuxPreloadWritablePaths(fs *fsVirtualizationPlan) []string {
	if !fs.AllowTemp {
		return fs.Writable
	}
	seen := make(map[string]struct{}, len(fs.Writable)+4)
	out := make([]string, 0, len(fs.Writable)+4)
	add := func(p string) {
		if p == "" {
			return
		}
		clean := canonPath(p)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	for _, p := range fs.Writable {
		add(p)
	}
	for _, p := range osTempRoots() {
		add(p)
	}
	return out
}

func linuxPreloadExisting(env []string) string {
	if env == nil {
		return os.Getenv("LD_PRELOAD")
	}
	for _, e := range env {
		if strings.HasPrefix(e, "LD_PRELOAD=") {
			return strings.TrimPrefix(e, "LD_PRELOAD=")
		}
	}
	return ""
}

func linuxPreloadEnv(lib string, s Spec, fs *fsVirtualizationPlan, readableManifest, readDenyManifest, writableManifest, upper string) []string {
	core := []string{
		"LD_PRELOAD=" + linuxPreloadMerge(lib, linuxPreloadExisting(s.Env)),
		"ISOBOXFS_MODE=enforce",
		"ISOBOXFS_READABLE=" + readableManifest,
		"ISOBOXFS_READ_DENY=" + readDenyManifest,
		"ISOBOXFS_WRITABLE=" + writableManifest,
	}
	if upper != "" {
		core = append(core, "ISOBOXFS_UPPER="+upper)
	}
	env := append([]string(nil), fs.Env...)
	return append(env, core...)
}

func linuxPreloadMerge(lib, existing string) string {
	if existing == "" {
		return lib
	}
	parts := strings.FieldsFunc(existing, func(r rune) bool {
		return r == ':' || r == ' ' || r == '\t' || r == '\n'
	})
	before := make([]string, 0, len(parts))
	after := make([]string, 0, len(parts))
	seen := map[string]struct{}{lib: {}}
	for _, p := range parts {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		if linuxPreloadBeforeIsoboxfs(p) {
			before = append(before, p)
		} else {
			after = append(after, p)
		}
	}
	merged := make([]string, 0, len(before)+1+len(after))
	merged = append(merged, before...)
	merged = append(merged, lib)
	merged = append(merged, after...)
	return strings.Join(merged, ":")
}

func linuxPreloadBeforeIsoboxfs(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.Contains(name, "fakeroot") ||
		strings.Contains(name, "fakechroot") ||
		strings.Contains(name, "cowdancer")
}

func linuxPreloadSmokeCommand(lib string, status int) (string, []string, []string) {
	return "/bin/sh", []string{"-c", "exit 0"}, []string{
		"LD_PRELOAD=" + lib,
		fmt.Sprintf("ISOBOXFS_DETECT=%d", status),
	}
}

// linuxPreloadSystemPaths returns the minimal host paths libisoboxfs
// must allow regardless of the spec's readable scopes: the dynamic linker
// data, the standard library directories, the isobox binary directory (which
// holds libisoboxfs.so so the loader can map it), and any executable-specific
// runtime candidates derived from the spec args.
func linuxPreloadSystemPaths(s Spec) []string {
	paths := []string{
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
		"/etc",
	}
	paths = append(paths, linuxRuntimePathCandidates(s)...)
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Dir(exe))
	}
	return paths
}

// linuxPreloadLocateLibisoboxfs resolves the LD_PRELOAD payload. The env
// override ISOBOX_LIBISOBOXFS wins and is trusted verbatim — useful when the
// operator stages the library outside the standard locations or when a test
// wants to assert resolution without producing a real file. Otherwise it
// walks a small, well-known candidate set and returns the first existing
// file, with a descriptive error listing what was tried when none match.
func linuxPreloadLocateLibisoboxfs(getenv func(string) string) (string, error) {
	if v := getenv("ISOBOX_LIBISOBOXFS"); v != "" {
		return v, nil
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "libisoboxfs.so"))
	}
	candidates = append(candidates,
		"/usr/local/lib/libisoboxfs.so",
		"/usr/lib/libisoboxfs.so",
	)
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("isobox: could not locate libisoboxfs.so (set ISOBOX_LIBISOBOXFS or install to /usr/local/lib or /usr/lib); searched: %s", strings.Join(candidates, ", "))
}

func unsupportedFSVirtualization(fs *fsVirtualizationPlan) error {
	kind := fsVirtualizationKind("")
	if fs != nil {
		kind = fs.Kind
	}
	return fmt.Errorf("isobox: filesystem virtualization kind %q is not implemented on this platform", kind)
}

// Linux filesystem view planning lives in linux_view.go; runtime setup remains
// in cow_linux_runtime_linux.go.
