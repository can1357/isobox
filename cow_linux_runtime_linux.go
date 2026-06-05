//go:build linux

package isobox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

func prepareLinuxNamespaceViewRuntime(_ *fsVirtualizationPlan, plan *Plan, s Spec, view linuxNamespaceView) (*fsVirtualizationRuntime, error) {
	if plan == nil || plan.gv == nil {
		return nil, fmt.Errorf("isobox: gvisor filesystem scopes require OCI execution")
	}
	rootfs, mounts, cleanup, err := prepareGvisorOCIFilesystemView(s, view)
	if err != nil {
		return nil, err
	}
	plan.gv.Rootfs = rootfs
	plan.gv.RootReadonly = true
	plan.gv.FSMounts = mounts
	return &fsVirtualizationRuntime{Cleanup: cleanup}, nil
}

func linuxPreloadSmokeTest(lib string) error {
	const detectStatus = 42
	name, args, env := linuxPreloadSmokeCommand(lib, detectStatus)
	cmd := exec.Command(name, args...)
	cmd.Env = appendEnv(os.Environ(), env)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == detectStatus {
		return nil
	}
	if err == nil {
		return fmt.Errorf("isobox: preload smoke test exited 0, want %d", detectStatus)
	}
	return fmt.Errorf("isobox: preload smoke test failed: %w", err)
}
