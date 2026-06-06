package isobox

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

func validateDockerRunscRuntime(ctx context.Context, argv []string) error {
	runtime, ok := dockerRunRuntime(argv)
	if !ok || runtime == "" {
		return fmt.Errorf("isobox: docker-runsc-ephemeral plan is missing --runtime")
	}
	out, err := exec.CommandContext(ctx, argv[0], "info", "--format", "{{json .Runtimes}}").Output()
	if err != nil {
		return fmt.Errorf("isobox: checking Docker runtime %q: %w", runtime, err)
	}
	if !dockerRuntimeInfoHas(string(out), runtime) {
		return fmt.Errorf("isobox: Docker runtime %q is not registered with this daemon", runtime)
	}
	return nil
}

func dockerRuntimeInfoHas(info, runtime string) bool {
	info = strings.TrimSpace(info)
	if info == "" || info == "null" {
		return false
	}
	var runtimes map[string]json.RawMessage
	if err := json.Unmarshal([]byte(info), &runtimes); err != nil {
		return false
	}
	_, ok := runtimes[runtime]
	return ok
}

func dockerRunRuntime(argv []string) (string, bool) {
	if len(argv) < 3 || argv[1] != "run" {
		return "", false
	}
	for i := 2; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			return "", false
		}
		if value, ok := strings.CutPrefix(arg, "--runtime="); ok {
			return value, true
		}
		if arg == "--runtime" {
			if i+1 < len(argv) {
				return argv[i+1], true
			}
			return "", false
		}
		if arg == "--rm" || arg == "--read-only" {
			continue
		}
		if strings.HasPrefix(arg, "--") {
			if strings.Contains(arg, "=") {
				continue
			}
			if dockerRunOptionTakesValue(arg) && i+1 < len(argv) {
				i++
			}
			continue
		}
		return "", false
	}
	return "", false
}
