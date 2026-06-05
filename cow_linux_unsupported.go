//go:build !linux

package isobox

import "fmt"

func prepareLinuxNamespaceView(fs *fsVirtualizationPlan, _ *Plan, _ Spec) (*fsVirtualizationRuntime, error) {
	return nil, unsupportedFSVirtualization(fs)
}

func prepareLinuxPreloadFallback(fs *fsVirtualizationPlan, _ *Plan, _ Spec) (*fsVirtualizationRuntime, error) {
	return nil, unsupportedFSVirtualization(fs)
}

func unsupportedFSVirtualization(fs *fsVirtualizationPlan) error {
	kind := fsVirtualizationKind("")
	if fs != nil {
		kind = fs.Kind
	}
	return fmt.Errorf("isobox: filesystem virtualization kind %q is not implemented on this platform", kind)
}
