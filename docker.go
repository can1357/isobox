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
const dockerRunscRuntimeEnv = "ISOBOX_DOCKER_RUNSC_RUNTIME"

type dockerPlan struct {
	ReadDeny []string
}

func compileDockerEphemeral(s Spec) (*Plan, error) {
	return compileDocker(s, BackendDockerEphemeral, os.Getenv(dockerRuntimeEnv), false)
}

func compileDockerRunscEphemeral(s Spec) (*Plan, error) {
	runtime := os.Getenv(dockerRunscRuntimeEnv)
	if runtime == "" {
		runtime = "runsc"
	}
	return compileDocker(s, BackendDockerRunscEphemeral, runtime, true)
}

func compileDocker(s Spec, backend Backend, runtime string, forceRunsc bool) (*Plan, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	label := string(backend)
	image := os.Getenv(dockerImageEnv)
	if image == "" {
		return nil, fmt.Errorf("isobox: %s requires %s", label, dockerImageEnv)
	}

	readable := dockerScopePaths(s.Readable)
	writable := dockerScopePaths(s.Writable)
	workDir := ""
	if s.Dir != "" {
		workDir = cleanDockerContainerPath(s.Dir)
		if !dockerPathUnderAnyScope(workDir, readable) && !dockerPathUnderAnyScope(workDir, writable) {
			return nil, fmt.Errorf("isobox: %s working directory %q must be under a readable or writable bind mount", label, s.Dir)
		}
	}

	uses := NewCapabilitySet()
	caveats := []string{
		fmt.Sprintf("%s runs the command inside the configured image; host executables and unmounted host paths are not available", label),
	}
	if len(s.MachAllow) > 0 {
		caveats = append(caveats, fmt.Sprintf("Mach service allow-list is macOS Seatbelt-only; ignored on %s", label))
	}
	if forceRunsc {
		uses = uses.Union(NewCapabilitySet(CapKernelIsolation))
		caveats = append(caveats, fmt.Sprintf("%s forces Docker runtime %q for gVisor userspace-kernel isolation; launch verifies the runtime name exists but trusts the Docker daemon's runtime registration", label, runtime))
	} else {
		switch runtime {
		case "runsc":
			caveats = append(caveats, "docker-ephemeral runtime=runsc provides user-space kernel isolation comparable to gVisor; use docker-runsc-ephemeral to make this a declared backend capability.")
		case "":
			caveats = append(caveats, "kernel.isolation is Docker VM/guest-kernel isolation, not gVisor userspace-kernel isolation; use docker-runsc-ephemeral to require gVisor via Docker")
		default:
			caveats = append(caveats, fmt.Sprintf("kernel.isolation uses Docker runtime %q, which is Docker VM/guest-kernel isolation unless that runtime provides userspace-kernel isolation", runtime))
		}
	}
	if strings.HasPrefix(s.Args[0], "/") {
		caveats = append(caveats, "absolute command paths are resolved inside the Docker image, not on the host")
	}
	if len(readable) > 0 {
		uses = uses.Union(NewCapabilitySet(CapFSReadScope))
		caveats = append(caveats, fmt.Sprintf("%s fs.read.scope exposes listed host paths as read-only bind mounts; container image paths remain readable", label))
	}
	if len(readable) == 0 && len(writable) == 0 {
		uses = uses.Union(NewCapabilitySet(CapIPCRestrict))
	} else {
		caveats = append(caveats, fmt.Sprintf("host filesystem scopes can expose host IPC endpoints such as Unix sockets or FIFOs; %s keeps --ipc=private but does not claim ipc.restrict for this plan", label))
	}
	if len(s.ReadDeny) > 0 {
		caveats = append(caveats, fmt.Sprintf("%s does not expose broad host reads, so requested read-deny paths are applied only as path masks inside mounted/container paths", label))
	}
	switch s.Write {
	case WriteNone:
		caveats = append(caveats, fmt.Sprintf("%s keeps the root filesystem read-only but still provides disposable tmpfs scratch at /tmp and /run", label))
		uses = uses.Union(NewCapabilitySet(CapFSWriteDeny))
	case WriteScope:
		uses = uses.Union(NewCapabilitySet(CapFSWriteScope))
		caveats = append(caveats, fmt.Sprintf("%s WriteScope persists writes through writable bind mounts only; other container paths remain read-only", label))
		caveats = append(caveats, "docker scoped writes are path/mount based; hardlinks or nested host mountpoints under writable paths can affect host objects outside the lexical scope")
	case WriteEphemeral:
		caveats = append(caveats, fmt.Sprintf("%s WriteEphemeral uses Docker's disposable container writable layer; writes are discarded with --rm; explicitly readable host paths remain read-only bind mounts and are not made ephemeral", label))
		uses = uses.Union(NewCapabilitySet(CapFSWriteEphemeral))
	case WriteOverlay:
		uses = uses.Union(NewCapabilitySet(CapFSWriteScope))
		caveats = append(caveats, fmt.Sprintf("%s has no hybrid shadow layer; writes outside writable bind mounts are denied by the read-only root", label))
		caveats = append(caveats, "docker scoped writes are path/mount based; hardlinks or nested host mountpoints under writable paths can affect host objects outside the lexical scope")
	}
	if s.NoExec {
		caveats = append(caveats, fmt.Sprintf("%s does not enforce proc.no_exec", label))
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
		if dockerPathUnderAnyScope(path, writable) {
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
		caveats = append(caveats, fmt.Sprintf("%s net.outbound denies TCP listen/accept/accept4 with a Docker seccomp profile; UDP bind may still be creatable, and the syscall-wide deny also blocks AF_UNIX stream servers", label))
	}

	argv = append(argv, image)
	argv = append(argv, s.Args...)

	return &Plan{
		Backend: backend,
		Argv:    argv,
		Uses:    uses,
		Caveats: caveats,
		docker:  &dockerPlan{ReadDeny: dockerCanonPaths(s.ReadDeny)},
	}, nil
}

func dockerCanonPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = appendGrant(out, canonPath(path))
	}
	return out
}

// dockerScopePaths normalizes readable/writable bind-mount scopes as container
// paths. Unlike dockerCanonPaths (used for read-deny masks, which must lstat and
// shadow the real host file), bind mounts use the same path for src and dst, so
// they are kept as host-independent POSIX container paths: a Linux container
// must see the path the caller requested, and previewing the plan from a Windows
// host must not rewrite "/host" into a drive-qualified "D:\host".
func dockerScopePaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = appendGrant(out, cleanDockerContainerPath(path))
	}
	return out
}

func dockerBindMountSpec(path string, readonly bool) (string, error) {
	return dockerBindMountSpecPaths(path, path, readonly)
}

func dockerBindMountSpecPaths(src, dst string, readonly bool) (string, error) {
	if strings.ContainsAny(src, ",\r\n") || strings.ContainsAny(dst, ",\r\n") {
		return "", fmt.Errorf("isobox: docker bind mount path contains a comma or newline, which Docker --mount cannot represent safely")
	}
	mount := "type=bind,src=" + src + ",dst=" + dst
	if readonly {
		mount += ",readonly"
	}
	return mount, nil
}
