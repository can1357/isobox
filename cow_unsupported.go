//go:build !darwin

package isobox

func prepareMacOSAPFSWorkspaceClone(fs *fsVirtualizationPlan, _ *Plan, _ Spec) (*fsVirtualizationRuntime, error) {
	return nil, unsupportedFSVirtualization(fs)
}
