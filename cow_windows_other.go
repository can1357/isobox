//go:build !windows

package isobox

func prepareWindowsWorkspaceCopy(fs *fsVirtualizationPlan, _ *Plan, _ Spec) (*fsVirtualizationRuntime, error) {
	return nil, unsupportedFSVirtualization(fs)
}
