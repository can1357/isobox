//go:build !windows

package isobox

import (
	"context"
	"fmt"
)

func runAppContainer(ctx context.Context, plan *Plan, s Spec, streams Stdio) (int, error) {
	return -1, fmt.Errorf("isobox: appcontainer backend runs only on Windows")
}
