package isobox

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const dockerBinary = "docker"

const dockerImageEnv = "ISOBOX_DOCKER_IMAGE"
const dockerRuntimeEnv = "ISOBOX_DOCKER_RUNTIME"

func compileDockerEphemeral(s Spec) (*Plan, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	image := os.Getenv(dockerImageEnv)
	if image == "" {
		return nil, fmt.Errorf("isobox: docker-ephemeral requires %s", dockerImageEnv)
	}
	runtime := os.Getenv(dockerRuntimeEnv)

	readable := dockerCanonPaths(s.Readable)
	writable := dockerCanonPaths(s.Writable)
	workDir := ""
	if s.Dir != "" {
		workDir = canonPath(s.Dir)
		if !pathUnderAnyScope(workDir, readable) && !pathUnderAnyScope(workDir, writable) {
			return nil, fmt.Errorf("isobox: docker-ephemeral working directory %q must be under a readable or writable bind mount", s.Dir)
		}
	}

	uses := NewCapabilitySet()
	caveats := []string{
		"docker-ephemeral runs the command inside the configured image; host executables and unmounted host paths are not available",
	}
	if len(s.MachAllow) > 0 {
		caveats = append(caveats, "Mach service allow-list is macOS Seatbelt-only; ignored on docker-ephemeral")
	}

	switch runtime {
	case "runsc":
		caveats = append(caveats, "docker-ephemeral runtime=runsc provides user-space kernel isolation comparable to gVisor; isobox does not advertise this as a capability because the runtime is host-configured, not declared by the spec.")
	case "":
		caveats = append(caveats, "kernel.isolation is Docker VM/guest-kernel isolation, not gVisor userspace-kernel isolation; set ISOBOX_DOCKER_RUNTIME=runsc to request gVisor when Docker provides that runtime")
	default:
		caveats = append(caveats, fmt.Sprintf("kernel.isolation uses Docker runtime %q, which is Docker VM/guest-kernel isolation unless that runtime provides userspace-kernel isolation", runtime))
	}
	if strings.HasPrefix(s.Args[0], "/") {
		caveats = append(caveats, "absolute command paths are resolved inside the Docker image, not on the macOS host")
	}
	if len(readable) > 0 {
		uses = uses.Union(NewCapabilitySet(CapFSReadScope))
		caveats = append(caveats, "docker-ephemeral fs.read.scope exposes listed host paths as read-only bind mounts; container image paths remain readable")
	}
	if len(readable) == 0 && len(writable) == 0 {
		uses = uses.Union(NewCapabilitySet(CapIPCRestrict))
	} else {
		caveats = append(caveats, "host filesystem scopes can expose host IPC endpoints such as Unix sockets or FIFOs; docker-ephemeral keeps --ipc=private but does not claim ipc.restrict for this plan")
	}
	if len(s.ReadDeny) > 0 {
		caveats = append(caveats, "docker-ephemeral does not expose broad host reads, so requested read-deny paths are not applied")
	}
	switch s.Write {
	case WriteNone:
		caveats = append(caveats, "docker-ephemeral keeps the root filesystem read-only but still provides disposable tmpfs scratch at /tmp and /run")
		uses = uses.Union(NewCapabilitySet(CapFSWriteDeny))
	case WriteScope:
		uses = uses.Union(NewCapabilitySet(CapFSWriteScope))
		caveats = append(caveats, "docker-ephemeral WriteScope persists writes through writable bind mounts only; other container paths remain read-only")
	case WriteEphemeral:
		caveats = append(caveats, "docker-ephemeral WriteEphemeral uses Docker's disposable container writable layer; writes are discarded with --rm; explicitly readable host paths remain read-only bind mounts and are not made ephemeral")
		uses = uses.Union(NewCapabilitySet(CapFSWriteEphemeral))
	case WriteOverlay:
		uses = uses.Union(NewCapabilitySet(CapFSWriteScope))
		caveats = append(caveats, "docker-ephemeral has no hybrid shadow layer; writes outside writable bind mounts are denied by the read-only root")
	}
	if s.NoExec {
		caveats = append(caveats, "docker-ephemeral does not enforce proc.no_exec")
	}

	argv := []string{
		dockerBinary,
		"run",
		"--rm",
		"--name", stableSpecID("isobox", s),
		"--ipc", "private",
	}
	if runtime != "" {
		argv = append(argv, "--runtime", runtime)
	}
	if s.Write != WriteEphemeral {
		argv = append(argv, "--read-only")
	}
	switch s.Write {
	case WriteNone, WriteEphemeral:
		argv = append(argv,
			"--tmpfs", "/tmp",
			"--tmpfs", "/run",
		)
	case WriteScope, WriteOverlay:
		if s.AllowTemp {
			argv = append(argv, "--tmpfs", "/tmp")
		}
	}
	for _, path := range readable {
		if pathUnderAnyScope(path, writable) {
			continue
		}
		mount, err := dockerBindMountSpec(path, true)
		if err != nil {
			return nil, err
		}
		argv = append(argv, "--mount", mount)
	}
	for _, path := range writable {
		mount, err := dockerBindMountSpec(path, false)
		if err != nil {
			return nil, err
		}
		argv = append(argv, "--mount", mount)
	}
	if workDir != "" {
		argv = append(argv, "--workdir", workDir)
	}

	if s.CPUs > 0 {
		argv = append(argv, "--cpus", strconv.FormatFloat(s.CPUs, 'f', -1, 64))
		uses = uses.Union(NewCapabilitySet(CapResCPU))
	}
	if s.MemoryBytes > 0 {
		argv = append(argv, "--memory", strconv.FormatInt(s.MemoryBytes, 10), "--memory-swap", strconv.FormatInt(s.MemoryBytes, 10))
		uses = uses.Union(NewCapabilitySet(CapResMemory))
	}

	switch s.Net {
	case NetDisable:
		argv = append(argv, "--network", "none")
		uses = uses.Union(NewCapabilitySet(CapNetDisable))
	case NetEnable:
		uses = uses.Union(NewCapabilitySet(CapNetEnable))
	case NetOutbound:
		argv = append(argv, "--security-opt", dockerSeccompSecurityOpt())
		uses = uses.Union(NewCapabilitySet(CapNetOutbound))
		caveats = append(caveats, "docker-ephemeral net.outbound denies TCP listen/accept/accept4 with a Docker seccomp profile; UDP bind may still be creatable, and the syscall-wide deny also blocks AF_UNIX stream servers")
	}

	argv = append(argv, image)
	argv = append(argv, s.Args...)

	return &Plan{
		Backend: BackendDockerEphemeral,
		Argv:    argv,
		Uses:    uses,
		Caveats: caveats,
	}, nil
}

func dockerCanonPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = appendGrant(out, canonPath(path))
	}
	return out
}

func dockerBindMountSpec(path string, readonly bool) (string, error) {
	if strings.ContainsAny(path, ",\r\n") {
		return "", fmt.Errorf("isobox: docker-ephemeral bind mount path %q contains a comma or newline, which Docker --mount cannot represent safely", path)
	}
	mount := "type=bind,src=" + path + ",dst=" + path
	if readonly {
		mount += ",readonly"
	}
	return mount, nil
}
