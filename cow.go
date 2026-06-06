package isobox

import (
	"fmt"
	"os"
	"strings"
)

// fsVirtualizationKind identifies the internal filesystem virtualization
// mechanism a backend compiler requests for a Plan. The value is pure compile
// time intent; preparation happens in Runner.Run immediately before exec.
type fsVirtualizationKind string

const (
	fsVirtualizationNone                 fsVirtualizationKind = ""
	fsVirtualizationMacOSAPFSClone       fsVirtualizationKind = "macos-apfs-workspace-clone"
	fsVirtualizationLinuxNamespaceView   fsVirtualizationKind = "linux-namespace-view"
	fsVirtualizationLinuxPreloadFallback fsVirtualizationKind = "linux-preload-fallback"
	fsVirtualizationWindowsWorkspaceCopy fsVirtualizationKind = "windows-workspace-copy"
)

// fsVirtualizationPlan is inspectable compiler output. It must not hold temp
// directories, cleanup hooks, open descriptors, or other runtime-only state.
type fsVirtualizationPlan struct {
	Kind          fsVirtualizationKind
	WorkspaceRoot string
	Readable      []string
	ReadDeny      []string
	Writable      []string
	AllowTemp     bool
	Env           []string
	Caveats       []string
}

// fsVirtualizationRuntime is the prepared state used for one process launch.
type fsVirtualizationRuntime struct {
	Env     []string
	Dir     string
	Caveats []string
	Cleanup func() error
}

func prepareFSVirtualization(plan *Plan, s Spec) (*fsVirtualizationRuntime, error) {
	if plan == nil || plan.fs == nil || plan.fs.Kind == fsVirtualizationNone {
		return nil, nil
	}

	fs := plan.fs
	switch fs.Kind {
	case fsVirtualizationMacOSAPFSClone:
		return prepareMacOSAPFSWorkspaceClone(fs, plan, s)
	case fsVirtualizationLinuxNamespaceView:
		return prepareLinuxNamespaceView(fs, plan, s)
	case fsVirtualizationLinuxPreloadFallback:
		return prepareLinuxPreloadFallback(fs, plan, s)
	case fsVirtualizationWindowsWorkspaceCopy:
		return prepareWindowsWorkspaceCopy(fs, plan, s)
	default:
		return nil, fmt.Errorf("isobox: unknown filesystem virtualization kind %q", fs.Kind)
	}
}

func appendPlanFSCaveats(plan *Plan, runtime *fsVirtualizationRuntime) {
	if plan == nil {
		return
	}
	if plan.fs != nil && len(plan.fs.Caveats) > 0 {
		plan.Caveats = append(plan.Caveats, plan.fs.Caveats...)
	}
	if runtime != nil && len(runtime.Caveats) > 0 {
		plan.Caveats = append(plan.Caveats, runtime.Caveats...)
	}
}

func replacePlanPlaceholder(plan *Plan, placeholder, value string) {
	if plan == nil {
		return
	}
	if plan.Profile != "" {
		plan.Profile = strings.ReplaceAll(plan.Profile, placeholder, value)
	}
	for i, arg := range plan.Argv {
		if strings.Contains(arg, placeholder) {
			plan.Argv[i] = strings.ReplaceAll(arg, placeholder, value)
		}
	}
	if plan.ac != nil {
		plan.ac.Exe = strings.ReplaceAll(plan.ac.Exe, placeholder, value)
		plan.ac.WorkDir = strings.ReplaceAll(plan.ac.WorkDir, placeholder, value)
		replaceStringSlicePlaceholder(plan.ac.Argv, placeholder, value)
		replaceStringSlicePlaceholder(plan.ac.ReadGrants, placeholder, value)
		replaceStringSlicePlaceholder(plan.ac.WriteGrants, placeholder, value)
	}
}

func replaceStringSlicePlaceholder(items []string, placeholder, value string) {
	for i, item := range items {
		if strings.Contains(item, placeholder) {
			items[i] = strings.ReplaceAll(item, placeholder, value)
		}
	}
}

func commandEnv(userEnv []string, fsEnv []string) []string {
	if len(fsEnv) == 0 {
		if userEnv == nil {
			return nil
		}
		return append([]string(nil), userEnv...)
	}

	base := userEnv
	if base == nil {
		base = os.Environ()
	}
	return appendEnv(base, fsEnv)
}

func appendEnv(base []string, extra []string) []string {
	if len(base) == 0 {
		return append([]string(nil), extra...)
	}
	out := append([]string(nil), base...)
	for _, env := range extra {
		key, ok := envKey(env)
		if !ok {
			out = append(out, env)
			continue
		}
		prefix := key + "="
		n := 0
		for _, existing := range out {
			if !strings.HasPrefix(existing, prefix) {
				out[n] = existing
				n++
			}
		}
		out = append(out[:n], env)
	}
	return out
}

func envKey(env string) (string, bool) {
	if i := strings.IndexByte(env, '='); i > 0 {
		return env[:i], true
	}
	return "", false
}
