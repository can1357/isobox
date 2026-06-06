//go:build !darwin

package isobox

import (
	"context"
	"os/exec"
)

func runResourceWatchedCommand(_ context.Context, cmd *exec.Cmd, _ *resourceWatchdogPlan) error {
	return cmd.Run()
}
