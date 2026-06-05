package isobox

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestLinuxPathInScopeUsesComponentBoundaries(t *testing.T) {
	scopes := []string{"/work", "/tmp/x"}
	cases := []struct {
		path string
		want bool
	}{
		{"/work", true},
		{"/work/file", true},
		{"/work/dir/file", true},
		{"/worker", false},
		{"/tmp/x", true},
		{"/tmp/x/y", true},
		{"/tmp/xy", false},
		{"/", false},
	}
	for _, tc := range cases {
		if got := pathInLinuxScope(tc.path, scopes); got != tc.want {
			t.Fatalf("pathInLinuxScope(%q)=%v, want %v", tc.path, got, tc.want)
		}
	}
	if !pathInLinuxScope("/anything", []string{"/"}) {
		t.Fatal("root scope should match every path")
	}
}

func TestLinuxNamespaceViewPlanMountsReadableAndWritable(t *testing.T) {
	fs, err := newLinuxNamespaceViewFSPlan(Spec{
		Readable: []string{"/read", "/shared"},
		Write:    WriteScope,
		Writable: []string{"/write", "/shared"},
	})
	if err != nil {
		t.Fatal(err)
	}
	view := buildLinuxNamespaceView(fs)
	if view.ReadHost {
		t.Fatal("scoped Readable must not expose broad host reads")
	}
	want := []linuxViewMount{
		{Source: "/read", Target: "/read", Mode: linuxViewMountReadOnly},
		{Source: "/shared", Target: "/shared", Mode: linuxViewMountReadWrite},
		{Source: "/write", Target: "/write", Mode: linuxViewMountReadWrite},
	}
	if !reflect.DeepEqual(view.Mounts, want) {
		t.Fatalf("mounts=%#v, want %#v", view.Mounts, want)
	}
}

func TestLinuxNamespaceViewPlanBroadReadWithScopedWrites(t *testing.T) {
	fs, err := newLinuxNamespaceViewFSPlan(Spec{Write: WriteScope, Writable: []string{"/write"}})
	if err != nil {
		t.Fatal(err)
	}
	view := buildLinuxNamespaceView(fs)
	if !view.ReadHost {
		t.Fatal("empty Readable should preserve broad host read semantics")
	}
	want := []linuxViewMount{{Source: "/write", Target: "/write", Mode: linuxViewMountReadWrite}}
	if !reflect.DeepEqual(view.Mounts, want) {
		t.Fatalf("mounts=%#v, want %#v", view.Mounts, want)
	}
}

func TestLinuxNamespaceViewPlanAllowTemp(t *testing.T) {
	fs, err := newLinuxNamespaceViewFSPlan(Spec{Readable: []string{"/read"}, AllowTemp: true})
	if err != nil {
		t.Fatal(err)
	}
	view := buildLinuxNamespaceView(fs)
	for _, root := range osTempRoots() {
		found := false
		for _, m := range view.Mounts {
			if m.Source == root && m.Mode == linuxViewMountReadWrite {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("temp root %q missing from %#v", root, view.Mounts)
		}
	}
}

func TestLinuxRuntimePathCandidatesStaySpecific(t *testing.T) {
	paths := linuxRuntimePathCandidates(Spec{Args: []string{"/bin/sh"}, Dir: "/work"})
	// /lib and /usr/lib are intentionally candidates: the dynamic-linker closure
	// needs them (see TestLinuxRuntimePathCandidatesCoversDynamicELFClosure), and
	// the os.Lstat filter in appendLinuxRuntimeMounts drops them when absent. Only
	// the binary search dirs and the workspace must never be implicitly broadened.
	for _, broad := range []string{"/bin", "/usr/bin", "/work"} {
		if hasGvisorString(paths, broad) {
			t.Fatalf("runtime paths must not include broad or implicit scope %q: %v", broad, paths)
		}
	}
	if !hasGvisorString(paths, "/bin/sh") {
		t.Fatalf("runtime paths should include the exact executable path: %v", paths)
	}
}

func TestLinuxGvisorOCIBroadReadWriteScopeMounts(t *testing.T) {
	tmp := t.TempDir()
	writeDir := filepath.Join(tmp, "write")
	if err := os.Mkdir(writeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fs, err := newLinuxNamespaceViewFSPlan(Spec{Write: WriteScope, Writable: []string{writeDir}})
	if err != nil {
		t.Fatal(err)
	}
	rootfs, mounts, cleanup, err := prepareGvisorOCIFilesystemView(Spec{Write: WriteScope, Writable: []string{writeDir}}, buildLinuxNamespaceView(fs))
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatal(err)
	}
	if rootfs != "/" {
		t.Fatalf("broad-read rootfs=%q, want /", rootfs)
	}
	if !hasOCIBindMount(mounts, writeDir, writeDir, "rw") {
		t.Fatalf("rw writable bind missing from %#v", mounts)
	}
	gv := newGvisorOCIPlan(Spec{Args: []string{"x"}, Write: WriteScope, Writable: []string{writeDir}})
	gv.Rootfs = rootfs
	gv.RootReadonly = true
	gv.FSMounts = mounts
	cfg := gvisorOCIConfig(Spec{Args: []string{"x"}, Write: WriteScope, Writable: []string{writeDir}}, gv, "")
	if cfg.Root.Path != "/" || !cfg.Root.Readonly {
		t.Fatalf("broad-read OCI root=%#v, want readonly /", cfg.Root)
	}
	if !hasOCIBindMount(cfg.Mounts, writeDir, writeDir, "rw") {
		t.Fatalf("rw writable bind missing from OCI config %#v", cfg.Mounts)
	}
}

func TestLinuxGvisorOCIReadDenyMountsObscureSensitivePaths(t *testing.T) {
	tmp := t.TempDir()
	secretDir := filepath.Join(tmp, "secret-dir")
	secretFile := filepath.Join(tmp, "token")
	workDir := filepath.Join(tmp, "work")
	for _, dir := range []string{secretDir, workDir} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(secretFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	fs, err := newLinuxNamespaceViewFSPlan(Spec{
		ReadDeny: []string{secretDir, secretFile},
		Write:    WriteOverlay,
		Writable: []string{workDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	rootfs, mounts, cleanup, err := prepareGvisorOCIFilesystemView(Spec{}, buildLinuxNamespaceView(fs))
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatal(err)
	}
	if rootfs != "/" {
		t.Fatalf("broad-read read-deny rootfs=%q, want /", rootfs)
	}
	if !hasOCIBindDestination(mounts, secretDir, "ro") {
		t.Fatalf("read-deny dir mount missing from %#v", mounts)
	}
	if !hasOCIBindDestination(mounts, secretFile, "ro") {
		t.Fatalf("read-deny file mount missing from %#v", mounts)
	}
}

func TestLinuxGvisorOCIReadScopeUsesTempRootAndBinds(t *testing.T) {
	tmp := t.TempDir()
	readDir := filepath.Join(tmp, "read")
	writeDir := filepath.Join(tmp, "write")
	if err := os.Mkdir(readDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(writeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fs, err := newLinuxNamespaceViewFSPlan(Spec{
		Args:     []string{"/bin/sh"},
		Readable: []string{readDir},
		Write:    WriteScope,
		Writable: []string{writeDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	rootfs, mounts, cleanup, err := prepareGvisorOCIFilesystemView(Spec{Args: []string{"/bin/sh"}}, buildLinuxNamespaceView(fs))
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatal(err)
	}
	if rootfs == "" || rootfs == "/" {
		t.Fatalf("read-scope rootfs=%q, want temp root", rootfs)
	}
	if info, err := os.Stat(rootfs); err != nil || !info.IsDir() {
		t.Fatalf("rootfs %q missing: info=%#v err=%v", rootfs, info, err)
	}
	if !hasOCIBindMount(mounts, readDir, readDir, "ro") {
		t.Fatalf("ro readable bind missing from %#v", mounts)
	}
	if !hasOCIBindMount(mounts, writeDir, writeDir, "rw") {
		t.Fatalf("rw writable bind missing from %#v", mounts)
	}
	if _, err := os.Stat(filepath.Join(rootfs, strings.TrimPrefix(readDir, string(filepath.Separator)))); err != nil {
		t.Fatalf("read mount placeholder missing: %v", err)
	}
	gv := newGvisorOCIPlan(Spec{Args: []string{"/bin/sh"}, Readable: []string{readDir}})
	gv.Rootfs = rootfs
	gv.RootReadonly = true
	gv.FSMounts = mounts
	cfg := gvisorOCIConfig(Spec{Args: []string{"/bin/sh"}, Readable: []string{readDir}, Dir: readDir}, gv, "")
	if cfg.Root.Path != rootfs || !cfg.Root.Readonly {
		t.Fatalf("read-scope OCI root=%#v, want readonly temp root", cfg.Root)
	}
	if cfg.Process.Cwd != readDir {
		t.Fatalf("process cwd=%q, want container path %q", cfg.Process.Cwd, readDir)
	}
}

func TestLinuxNamespaceViewRuntimePreparesOCIRoot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux OCI filesystem view preparation requires Linux runtime")
	}
	fs, err := newLinuxNamespaceViewFSPlan(Spec{Readable: []string{"/"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = prepareLinuxNamespaceView(fs, &Plan{gv: newGvisorOCIPlan(Spec{Args: []string{"x"}})}, Spec{Readable: []string{"/"}})
	if err != nil {
		t.Skipf("linux OCI filesystem view unavailable: %v", err)
	}
}

func hasOCIBindMount(mounts []ociMount, source, destination, option string) bool {
	for _, m := range mounts {
		if m.Type != "bind" || m.Source != source || m.Destination != destination {
			continue
		}
		for _, opt := range m.Options {
			if opt == option {
				return true
			}
		}
	}
	return false
}

func hasOCIBindDestination(mounts []ociMount, destination, option string) bool {
	for _, m := range mounts {
		if m.Type != "bind" || m.Destination != destination {
			continue
		}
		for _, opt := range m.Options {
			if opt == option {
				return true
			}
		}
	}
	return false
}

func TestPreloadFallbackManifestFormat(t *testing.T) {
	got := linuxPreloadManifestBytes([]string{"/a", "/b"})
	want := []byte("/a\n/b\n")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("manifest = %q, want %q", got, want)
	}
	if linuxPreloadManifestBytes(nil) != nil {
		t.Fatalf("empty input should produce nil manifest bytes")
	}
	if linuxPreloadManifestBytes([]string{}) != nil {
		t.Fatalf("zero-length input should produce nil manifest bytes")
	}
}

func TestPreloadFallbackMergeLDPreloadOrdering(t *testing.T) {
	got := linuxPreloadMerge("/isobox/libisoboxfs.so", strings.Join([]string{
		"/lib/libother.so",
		"/usr/lib/libfakeroot.so",
		"/isobox/libisoboxfs.so",
		"/usr/lib/libfakechroot.so",
		"/usr/lib/cowdancer/libcowdancer.so",
		"/lib/libafter.so",
	}, ":"))
	want := "/usr/lib/libfakeroot.so:/usr/lib/libfakechroot.so:/usr/lib/cowdancer/libcowdancer.so:/isobox/libisoboxfs.so:/lib/libother.so:/lib/libafter.so"
	if got != want {
		t.Fatalf("merged LD_PRELOAD=%q, want %q", got, want)
	}
}

func TestPreloadFallbackReadDenyEnvAndManifest(t *testing.T) {
	fs := &fsVirtualizationPlan{ReadDeny: []string{"/secret", "/token"}}
	env := linuxPreloadEnv("/isobox/libisoboxfs.so", Spec{}, fs, "/tmp/readable", "/tmp/read-deny", "/tmp/writable", "")
	if !hasGvisorString(env, "ISOBOXFS_READ_DENY=/tmp/read-deny") {
		t.Fatalf("ISOBOXFS_READ_DENY env missing from %v", env)
	}
	want := []byte("/secret\n/token\n")
	if got := linuxPreloadManifestBytes(fs.ReadDeny); !reflect.DeepEqual(got, want) {
		t.Fatalf("read-deny manifest=%q, want %q", got, want)
	}
}

func TestPreloadFallbackWritablePathsIncludeAllowTemp(t *testing.T) {
	fs := &fsVirtualizationPlan{Writable: []string{"/work"}, AllowTemp: true}
	got := linuxPreloadWritablePaths(fs)
	if len(got) == 0 || got[0] != canonPath("/work") {
		t.Fatalf("writable paths should start with explicit scope; got %v", got)
	}
	for _, root := range osTempRoots() {
		if !hasGvisorString(got, canonPath(root)) {
			t.Fatalf("writable paths missing temp root %q: %v", root, got)
		}
	}
}

func TestPreloadFallbackSmokeCommandConstruction(t *testing.T) {
	name, args, env := linuxPreloadSmokeCommand("/isobox/libisoboxfs.so", 42)
	if name != "/bin/sh" {
		t.Fatalf("smoke command name=%q, want /bin/sh", name)
	}
	if !reflect.DeepEqual(args, []string{"-c", "exit 0"}) {
		t.Fatalf("smoke command args=%q", args)
	}
	if !hasGvisorString(env, "LD_PRELOAD=/isobox/libisoboxfs.so") || !hasGvisorString(env, "ISOBOXFS_DETECT=42") {
		t.Fatalf("smoke command env missing preload or detect status: %v", env)
	}
}

func TestPreloadFallbackLocatesLibisoboxfs(t *testing.T) {
	t.Setenv("ISOBOX_LIBISOBOXFS", "/tmp/x.so")
	got, err := linuxPreloadLocateLibisoboxfs(os.Getenv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/tmp/x.so" {
		t.Fatalf("locator returned %q, want /tmp/x.so", got)
	}

	// Empty override falls through to file probing; the file must not exist
	// in any of the well-known locations under the test sandbox, so we
	// expect a descriptive error rather than a stale path.
	t.Setenv("ISOBOX_LIBISOBOXFS", "")
	if _, err := linuxPreloadLocateLibisoboxfs(func(string) string { return "" }); err == nil {
		t.Fatalf("locator should fail when no libisoboxfs.so candidate exists; environment has none")
	} else if !strings.Contains(err.Error(), "libisoboxfs.so") {
		t.Fatalf("error should mention libisoboxfs.so: %v", err)
	}
}

func TestPreloadFallbackSelectionTrigger(t *testing.T) {
	spec := Spec{Args: []string{"echo", "hi"}, Readable: []string{"/a"}}

	t.Setenv("ISOBOX_PRELOAD_FALLBACK", "")
	plan, err := compileGvisor(spec)
	if err != nil {
		t.Fatalf("compileGvisor without trigger: %v", err)
	}
	if plan.fs == nil {
		t.Fatalf("Readable spec must produce an fs virtualization plan")
	}
	if plan.fs.Kind != fsVirtualizationLinuxNamespaceView {
		t.Fatalf("without ISOBOX_PRELOAD_FALLBACK fs.Kind = %q, want %q",
			plan.fs.Kind, fsVirtualizationLinuxNamespaceView)
	}
	for _, c := range plan.Caveats {
		if strings.Contains(c, "ISOBOX_PRELOAD_FALLBACK") {
			t.Fatalf("namespace plan must not emit the preload trigger caveat: %q", c)
		}
	}

	t.Setenv("ISOBOX_PRELOAD_FALLBACK", "1")
	plan, err = compileGvisor(spec)
	if err != nil {
		t.Fatalf("compileGvisor with trigger: %v", err)
	}
	if plan.fs == nil || plan.fs.Kind != fsVirtualizationLinuxPreloadFallback {
		t.Fatalf("with ISOBOX_PRELOAD_FALLBACK=1 fs.Kind = %v, want %q",
			plan.fs, fsVirtualizationLinuxPreloadFallback)
	}
	found := false
	for _, c := range plan.Caveats {
		if strings.Contains(c, "ISOBOX_PRELOAD_FALLBACK=1") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("preload selection caveat missing from %v", plan.Caveats)
	}

	// Other env values must NOT trigger the fallback.
	t.Setenv("ISOBOX_PRELOAD_FALLBACK", "true")
	plan, err = compileGvisor(spec)
	if err != nil {
		t.Fatalf("compileGvisor with non-1 trigger: %v", err)
	}
	if plan.fs.Kind != fsVirtualizationLinuxNamespaceView {
		t.Fatalf("ISOBOX_PRELOAD_FALLBACK=true must not trigger the fallback; got %q", plan.fs.Kind)
	}
}

func TestPreloadFallbackReadablePathsIncludeSystemDirs(t *testing.T) {
	fs := &fsVirtualizationPlan{Readable: []string{"/work"}}
	got := linuxPreloadReadablePaths(Spec{Args: []string{"echo"}}, fs)
	have := func(p string) bool {
		for _, g := range got {
			if g == p {
				return true
			}
		}
		return false
	}
	// The explicit scope must lead, then the minimum system paths.
	if len(got) == 0 || got[0] != canonPath("/work") {
		t.Fatalf("readable paths should start with explicit scope; got %v", got)
	}
	for _, sys := range []string{"/lib", "/usr/lib", "/etc"} {
		if !have(canonPath(sys)) {
			t.Fatalf("readable paths missing required system dir %q: %v", sys, got)
		}
	}
	// Dedup invariant: no duplicates.
	seen := map[string]struct{}{}
	for _, p := range got {
		if _, dup := seen[p]; dup {
			t.Fatalf("duplicate path %q in readable manifest %v", p, got)
		}
		seen[p] = struct{}{}
	}
}

func TestPreloadFallbackReadablePathsEmptyMeansBroadRead(t *testing.T) {
	fs := &fsVirtualizationPlan{}
	if got := linuxPreloadReadablePaths(Spec{Args: []string{"echo"}}, fs); got != nil {
		t.Fatalf("empty explicit readable scope should produce empty manifest paths, got %v", got)
	}
}
