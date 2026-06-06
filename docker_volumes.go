package isobox

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path"
	"strings"
)

func validateDockerReadOnlyImageVolumes(ctx context.Context, argv []string) error {
	if !dockerArgvHas(argv, "--read-only") {
		return nil
	}
	image, ok := dockerRunImage(argv)
	if !ok {
		return nil
	}
	volumes, err := inspectDockerImageVolumes(ctx, argv[0], image)
	if err != nil {
		return err
	}
	violations := dockerReadOnlyVolumeViolations(argv, volumes)
	if len(violations) == 0 {
		return nil
	}
	return fmt.Errorf("isobox: docker image %q declares writable VOLUME %q, but this plan uses --read-only; use an image without that VOLUME or explicitly allow the path with Writable/AllowTemp", image, violations[0])
}

func inspectDockerImageVolumes(ctx context.Context, docker, image string) ([]string, error) {
	out, err := exec.CommandContext(ctx, docker, "image", "inspect", image, "--format", "{{json .Config.Volumes}}").Output()
	if err != nil {
		return nil, fmt.Errorf("isobox: inspecting docker image volumes for %q: %w", image, err)
	}
	text := strings.TrimSpace(string(out))
	if text == "" || text == "null" {
		return nil, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, fmt.Errorf("isobox: parsing docker image volumes for %q: %w", image, err)
	}
	volumes := make([]string, 0, len(raw))
	for volume := range raw {
		volumes = append(volumes, cleanDockerContainerPath(volume))
	}
	return volumes, nil
}

func dockerReadOnlyVolumeViolations(argv []string, volumes []string) []string {
	allowed := dockerWritableDestinations(argv)
	violations := make([]string, 0, len(volumes))
	for _, volume := range volumes {
		volume = cleanDockerContainerPath(volume)
		if volume == "" || dockerPathUnderAnyScope(volume, allowed) {
			continue
		}
		violations = append(violations, volume)
	}
	return violations
}

func dockerWritableDestinations(argv []string) []string {
	var out []string
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "--tmpfs":
			if i+1 < len(argv) {
				out = append(out, dockerMountDestinationValue(argv[i+1]))
				i++
			}
		case "--mount":
			if i+1 < len(argv) {
				spec := argv[i+1]
				if dockerMountIsWritable(spec) {
					out = append(out, dockerMountDestination(spec))
				}
				i++
			}
		}
	}
	return out
}

func dockerMountIsWritable(spec string) bool {
	readonly := false
	typ := ""
	for _, part := range strings.Split(spec, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			if part == "readonly" || part == "ro" {
				readonly = true
			}
			continue
		}
		switch key {
		case "type":
			typ = value
		case "readonly", "ro":
			if value == "" || value == "true" || value == "1" {
				readonly = true
			}
		}
	}
	if readonly {
		return false
	}
	return typ == "bind" || typ == "volume" || typ == "tmpfs"
}

func dockerMountDestination(spec string) string {
	for _, part := range strings.Split(spec, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch key {
		case "dst", "destination", "target":
			return cleanDockerContainerPath(value)
		}
	}
	return ""
}

func dockerMountDestinationValue(value string) string {
	if before, _, ok := strings.Cut(value, ":"); ok {
		value = before
	}
	return cleanDockerContainerPath(value)
}

func dockerRunImage(argv []string) (string, bool) {
	if len(argv) < 3 || argv[1] != "run" {
		return "", false
	}
	for i := 2; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
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
				continue
			}
			continue
		}
		return arg, true
	}
	return "", false
}

func dockerRunOptionTakesValue(option string) bool {
	switch option {
	case "--name", "--ipc", "--runtime", "--tmpfs", "--mount", "--workdir", "--cpus", "--memory", "--memory-swap", "--network", "--security-opt":
		return true
	default:
		return false
	}
}

func dockerArgvHas(argv []string, flag string) bool {
	for _, arg := range argv {
		if arg == flag {
			return true
		}
	}
	return false
}

func dockerPathUnderAnyScope(path string, scopes []string) bool {
	for _, scope := range scopes {
		if dockerPathUnderScope(path, scope) {
			return true
		}
	}
	return false
}

func dockerPathUnderScope(path, scope string) bool {
	path = cleanDockerContainerPath(path)
	scope = cleanDockerContainerPath(scope)
	if path == "" || scope == "" {
		return false
	}
	if path == scope {
		return true
	}
	if scope == "/" {
		return strings.HasPrefix(path, "/")
	}
	return strings.HasPrefix(path, scope+"/")
}

func cleanDockerContainerPath(p string) string {
	if p == "" {
		return ""
	}
	return path.Clean("/" + strings.TrimPrefix(p, "/"))
}
