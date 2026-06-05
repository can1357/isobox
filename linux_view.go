package isobox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type linuxViewMountMode string

const (
	linuxViewMountReadOnly  linuxViewMountMode = "ro"
	linuxViewMountReadWrite linuxViewMountMode = "rw"
)

type linuxViewMount struct {
	Source string
	Target string
	Mode   linuxViewMountMode
}

type linuxNamespaceView struct {
	ReadHost bool
	Mounts   []linuxViewMount
	ReadDeny []string
}

func newLinuxNamespaceViewFSPlan(s Spec) (*fsVirtualizationPlan, error) {
	readable := canonicalLinuxScopeList(s.Readable)
	readDeny := canonicalLinuxScopeList(s.ReadDeny)
	writable := canonicalLinuxScopeList(s.Writable)
	return &fsVirtualizationPlan{
		Kind:      fsVirtualizationLinuxNamespaceView,
		Readable:  readable,
		ReadDeny:  readDeny,
		Writable:  writable,
		AllowTemp: s.AllowTemp,
	}, nil
}

func buildLinuxNamespaceView(fs *fsVirtualizationPlan) linuxNamespaceView {
	if fs == nil {
		return linuxNamespaceView{ReadHost: true}
	}
	view := linuxNamespaceView{
		ReadHost: len(fs.Readable) == 0,
		ReadDeny: canonicalLinuxScopeList(fs.ReadDeny),
	}
	seen := make(map[string]linuxViewMountMode, len(fs.Readable)+len(fs.Writable)+4)
	for _, p := range canonicalLinuxScopeList(fs.Readable) {
		addLinuxViewMount(&view, seen, p, linuxViewMountReadOnly)
	}
	for _, p := range canonicalLinuxScopeList(fs.Writable) {
		addLinuxViewMount(&view, seen, p, linuxViewMountReadWrite)
	}
	if fs.AllowTemp {
		for _, p := range osTempRoots() {
			addLinuxViewMount(&view, seen, p, linuxViewMountReadWrite)
		}
	}
	sort.SliceStable(view.Mounts, func(i, j int) bool {
		if view.Mounts[i].Target == view.Mounts[j].Target {
			return view.Mounts[i].Mode < view.Mounts[j].Mode
		}
		return view.Mounts[i].Target < view.Mounts[j].Target
	})
	return view
}

func prepareGvisorOCIFilesystemView(s Spec, view linuxNamespaceView) (rootfs string, mounts []ociMount, cleanup func() error, err error) {
	cleanups := []func() error(nil)
	defer func() {
		if err != nil {
			_ = runLinuxViewCleanups(cleanups)
		}
	}()

	if view.ReadHost {
		rootfs = "/"
		mounts = linuxViewOCIMounts(coalesceLinuxViewMounts(view.Mounts))
	} else {
		rootfs, err = os.MkdirTemp("", "isobox-fs-view-")
		if err != nil {
			return "", nil, nil, fmt.Errorf("isobox: creating linux filesystem view rootfs: %w", err)
		}
		cleanups = append(cleanups, func() error { return os.RemoveAll(rootfs) })

		mountSpecs := append([]linuxViewMount(nil), view.Mounts...)
		mountSpecs = appendLinuxRuntimeMounts(mountSpecs, s)
		mountSpecs = coalesceLinuxViewMounts(mountSpecs)

		mounts = make([]ociMount, 0, len(mountSpecs))
		for _, m := range mountSpecs {
			if err := createLinuxViewPlaceholder(rootfs, m.Target, m.Source); err != nil {
				return "", nil, nil, err
			}
			mounts = append(mounts, linuxViewOCIMount(m))
		}
	}

	if len(view.ReadDeny) > 0 {
		var denyMounts []ociMount
		var denyCleanup func() error
		denyMounts, denyCleanup, err = linuxReadDenyOCIMounts(rootfs, view.ReadHost, view.ReadDeny)
		if err != nil {
			return "", nil, nil, err
		}
		if denyCleanup != nil {
			cleanups = append(cleanups, denyCleanup)
		}
		mounts = append(mounts, denyMounts...)
	}

	return rootfs, mounts, linuxViewCleanup(cleanups), nil
}

func linuxReadDenyOCIMounts(rootfs string, readHost bool, denied []string) ([]ociMount, func() error, error) {
	tmp, err := os.MkdirTemp("", "isobox-read-deny-")
	if err != nil {
		return nil, nil, fmt.Errorf("isobox: creating linux read-deny scratch: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(tmp) }

	mounts := make([]ociMount, 0, len(denied))
	for i, deniedPath := range canonicalLinuxScopeList(denied) {
		info, err := os.Lstat(deniedPath)
		if err != nil {
			continue
		}
		target := linuxViewTarget(deniedPath)
		if !readHost {
			if err := createLinuxViewPlaceholder(rootfs, target, deniedPath); err != nil {
				_ = cleanup()
				return nil, nil, err
			}
		}

		if info.IsDir() {
			source := filepath.Join(tmp, fmt.Sprintf("d%d", i))
			if err := os.Mkdir(source, 0o555); err != nil {
				_ = cleanup()
				return nil, nil, fmt.Errorf("isobox: creating linux read-deny dir: %w", err)
			}
			mounts = append(mounts, ociMount{
				Destination: target,
				Type:        "bind",
				Source:      source,
				Options:     []string{"rbind", "ro"},
			})
			continue
		}

		source := filepath.Join(tmp, fmt.Sprintf("f%d", i))
		if err := os.WriteFile(source, nil, 0o444); err != nil {
			_ = cleanup()
			return nil, nil, fmt.Errorf("isobox: creating linux read-deny file: %w", err)
		}
		mounts = append(mounts, ociMount{
			Destination: target,
			Type:        "bind",
			Source:      source,
			Options:     []string{"bind", "ro"},
		})
	}

	if len(mounts) == 0 {
		_ = cleanup()
		return nil, nil, nil
	}
	return mounts, cleanup, nil
}

func linuxViewCleanup(cleanups []func() error) func() error {
	if len(cleanups) == 0 {
		return nil
	}
	return func() error {
		return runLinuxViewCleanups(cleanups)
	}
}

func runLinuxViewCleanups(cleanups []func() error) error {
	var first error
	for i := len(cleanups) - 1; i >= 0; i-- {
		if err := cleanups[i](); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func linuxViewOCIMounts(viewMounts []linuxViewMount) []ociMount {
	if len(viewMounts) == 0 {
		return nil
	}
	mounts := make([]ociMount, 0, len(viewMounts))
	for _, m := range viewMounts {
		mounts = append(mounts, linuxViewOCIMount(m))
	}
	return mounts
}

func linuxViewOCIMount(m linuxViewMount) ociMount {
	options := []string{"rbind"}
	if m.Mode == linuxViewMountReadWrite {
		options = append(options, "rw")
	} else {
		options = append(options, "ro")
	}
	return ociMount{
		Destination: m.Target,
		Type:        "bind",
		Source:      m.Source,
		Options:     options,
	}
}

func appendLinuxRuntimeMounts(mounts []linuxViewMount, s Spec) []linuxViewMount {
	seen := make(map[string]linuxViewMountMode, len(mounts)+16)
	view := linuxNamespaceView{Mounts: append([]linuxViewMount(nil), mounts...)}
	for _, m := range mounts {
		seen[m.Source] = m.Mode
	}
	for _, p := range linuxRuntimePathCandidates(s) {
		if info, err := os.Lstat(p); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				if resolved, err := filepath.EvalSymlinks(p); err == nil {
					addLinuxViewMount(&view, seen, resolved, linuxViewMountReadOnly)
				}
			}
			addLinuxViewMount(&view, seen, p, linuxViewMountReadOnly)
		}
	}
	return view.Mounts
}

func linuxRuntimePathCandidates(s Spec) []string {
	// gVisor scoped-read mode boots a fresh rootfs assembled from the user's
	// --readable allowlist. To start a dynamically linked ELF the kernel needs
	// the executable itself plus the interpreter (ld-linux-*) and its library
	// closure, and glibc additionally consults /etc/ld.so.cache (+conf). The
	// caller filters non-existent paths via os.Lstat in appendLinuxRuntimeMounts,
	// so listing distro-specific multiarch dirs that may not exist is fine.
	paths := []string{
		"/etc/ld.so.cache",
		"/etc/ld.so.conf",
		"/etc/ld.so.conf.d",
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
		"/lib/x86_64-linux-gnu",
		"/usr/lib/x86_64-linux-gnu",
		"/lib/aarch64-linux-gnu",
		"/usr/lib/aarch64-linux-gnu",
	}
	if len(s.Args) > 0 {
		arg0 := s.Args[0]
		if filepath.IsAbs(arg0) {
			paths = append(paths, filepath.Clean(arg0))
		} else if arg0 != "" {
			if resolved, err := exec.LookPath(arg0); err == nil {
				paths = append(paths, filepath.Clean(resolved))
			}
		}
	}
	return paths
}

func coalesceLinuxViewMounts(mounts []linuxViewMount) []linuxViewMount {
	view := linuxNamespaceView{}
	seen := make(map[string]linuxViewMountMode, len(mounts))
	for _, m := range mounts {
		addLinuxViewMount(&view, seen, m.Source, m.Mode)
	}
	sort.SliceStable(view.Mounts, func(i, j int) bool {
		if view.Mounts[i].Target == view.Mounts[j].Target {
			return view.Mounts[i].Mode < view.Mounts[j].Mode
		}
		return view.Mounts[i].Target < view.Mounts[j].Target
	})
	return view.Mounts
}

func createLinuxViewPlaceholder(rootfs, target, source string) error {
	target = filepath.Clean(target)
	if target == string(filepath.Separator) {
		return nil
	}
	hostTarget := filepath.Join(rootfs, strings.TrimPrefix(target, string(filepath.Separator)))
	if err := os.MkdirAll(filepath.Dir(hostTarget), 0o755); err != nil {
		return fmt.Errorf("isobox: creating filesystem view mount parent: %w", err)
	}
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("isobox: inspecting filesystem view source %q: %w", source, err)
	}
	if info.IsDir() {
		if err := os.MkdirAll(hostTarget, 0o755); err != nil {
			return fmt.Errorf("isobox: creating filesystem view directory target: %w", err)
		}
		return nil
	}
	f, err := os.OpenFile(hostTarget, os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("isobox: creating filesystem view file target: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("isobox: closing filesystem view file target: %w", err)
	}
	return nil
}

func addLinuxViewMount(view *linuxNamespaceView, seen map[string]linuxViewMountMode, source string, mode linuxViewMountMode) {
	if source == "" {
		return
	}
	if old, ok := seen[source]; ok {
		if old == linuxViewMountReadWrite || mode == linuxViewMountReadOnly {
			return
		}
		seen[source] = linuxViewMountReadWrite
		for i := range view.Mounts {
			if view.Mounts[i].Source == source {
				view.Mounts[i].Mode = linuxViewMountReadWrite
				return
			}
		}
	}
	seen[source] = mode
	view.Mounts = append(view.Mounts, linuxViewMount{Source: source, Target: linuxViewTarget(source), Mode: mode})
}

func linuxViewTarget(source string) string {
	clean := filepath.Clean(source)
	if clean == string(filepath.Separator) {
		return clean
	}
	return clean
}

func canonicalLinuxScopeList(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		clean := canonPath(p)
		if runtime.GOOS == "windows" {
			clean = filepath.ToSlash(clean)
		}
		clean = filepath.Clean(clean)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}

func pathInLinuxScope(path string, scopes []string) bool {
	if len(scopes) == 0 {
		return false
	}
	clean := filepath.Clean(path)
	for _, scope := range scopes {
		scope = filepath.Clean(scope)
		if scope == string(filepath.Separator) || clean == scope {
			return true
		}
		if strings.HasPrefix(clean, scope+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
