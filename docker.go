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
	if s.Dir != "" {
		return nil, fmt.Errorf("isobox: docker-ephemeral cannot use host working directory %q; provide a directory inside the image", s.Dir)
	}

	image := os.Getenv(dockerImageEnv)
	if image == "" {
		return nil, fmt.Errorf("isobox: docker-ephemeral requires %s", dockerImageEnv)
	}
	runtime := os.Getenv(dockerRuntimeEnv)

	uses := NewCapabilitySet()
	caveats := []string{
		"docker-ephemeral runs the command inside the configured image; macOS host executables, working directories, and host paths are not mounted or copied into the container",
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
	if len(s.Readable) > 0 {
		caveats = append(caveats, "docker-ephemeral does not mount requested readable host paths; fs.read.scope parity is not applied")
	}
	if len(s.ReadDeny) > 0 {
		caveats = append(caveats, "docker-ephemeral does not expose broad host reads, so requested read-deny paths are not applied")
	}
	switch s.Write {
	case WriteNone:
		caveats = append(caveats, "docker-ephemeral keeps the root filesystem read-only but still provides disposable tmpfs scratch at /tmp and /run")
	case WriteScope:
		caveats = append(caveats, "docker-ephemeral does not persist requested writable host paths; using disposable container scratch only")
	case WriteEphemeral:
		caveats = append(caveats, "docker-ephemeral does not provide writable whole-filesystem ephemeral writes; root filesystem stays read-only with disposable tmpfs scratch at /tmp and /run only")
	case WriteOverlay:
		caveats = append(caveats, "docker-ephemeral does not persist requested writable host paths or provide hybrid shadow writes; using disposable container scratch only")
	}
	if s.NoExec {
		caveats = append(caveats, "docker-ephemeral does not enforce proc.no_exec")
	}

	argv := []string{
		dockerBinary,
		"run",
		"--rm",
		"--name", stableSpecID("isobox", s),
	}
	if runtime != "" {
		argv = append(argv, "--runtime", runtime)
	}
	argv = append(argv,
		"--read-only",
		"--tmpfs", "/tmp",
		"--tmpfs", "/run",
	)
	if s.CPUs > 0 {
		argv = append(argv, "--cpus", strconv.FormatFloat(s.CPUs, 'f', -1, 64))
		uses = uses.Union(NewCapabilitySet(CapResCPU))
	}
	if s.MemoryBytes > 0 {
		argv = append(argv, "--memory", strconv.FormatInt(s.MemoryBytes, 10))
		uses = uses.Union(NewCapabilitySet(CapResMemory))
	}

	switch s.Net {
	case NetDisable:
		argv = append(argv, "--network", "none")
		uses = uses.Union(NewCapabilitySet(CapNetDisable))
	case NetEnable:
		uses = uses.Union(NewCapabilitySet(CapNetEnable))
	case NetOutbound:
		uses = uses.Union(NewCapabilitySet(CapNetEnable))
		caveats = append(caveats, "net.outbound uses Docker's default bridge without published ports; inbound/listen is not additionally blocked inside the container")
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
