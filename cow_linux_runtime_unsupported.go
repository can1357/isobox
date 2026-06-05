//go:build !linux

package isobox

import "fmt"

func prepareLinuxNamespaceViewRuntime(fs *fsVirtualizationPlan, _ *Plan, _ Spec, _ linuxNamespaceView) (*fsVirtualizationRuntime, error) {
	return nil, fmt.Errorf("isobox: filesystem virtualization kind %q requires Linux gVisor OCI filesystem view support", fs.Kind)
}

func linuxPreloadSmokeTest(string) error {
	return fmt.Errorf("isobox: linux LD_PRELOAD fallback requires Linux runtime support")
}
