package isobox

import "os"

// gvisorBinary is the runsc executable name; overridable via the RUNSC env var
// at run time (see runner).
const gvisorBinary = "runsc"

// compileGvisor turns a Spec into a gVisor plan. Simple specs stay on
// `runsc do`; specs needing OCI seccomp, owned network namespaces, or scoped
// filesystem roots use a generated OCI bundle executed by `runsc run`.
func compileGvisor(s Spec) (*Plan, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	uses := NewCapabilitySet(CapKernelIsolation)
	var caveats []string
	if len(s.MachAllow) > 0 {
		caveats = append(caveats, "Mach service allow-list is macOS Seatbelt-only; ignored on gvisor")
	}
	var flags []string
	needsFSView := len(s.Readable) > 0 || len(s.ReadDeny) > 0 || s.Write == WriteScope || s.Write == WriteOverlay
	needsOCI := s.Net == NetOutbound || s.NoExec || needsFSView || s.CPUs > 0 || s.MemoryBytes > 0 || s.PIDs > 0
	var fs *fsVirtualizationPlan
	preloadFallback := false
	if needsFSView {
		var err error
		fs, err = newLinuxNamespaceViewFSPlan(s)
		if err != nil {
			return nil, err
		}
		if os.Getenv("ISOBOX_PRELOAD_FALLBACK") == "1" {
			fs.Kind = fsVirtualizationLinuxPreloadFallback
			preloadFallback = true
			caveats = append(caveats,
				"preload fallback selected via ISOBOX_PRELOAD_FALLBACK=1; LD_PRELOAD-based fs scope enforcement is best-effort: secure-exec/setuid binaries can ignore it, static binaries and direct syscalls can bypass wrappers, pre-opened descriptors remain usable, and directory enumeration or loader paths not wrapped by libisoboxfs may leak host state; native namespace view is preferred when available")
		}
	}
	if needsFSView {
		caveats = append(caveats, "host filesystem scopes can expose host IPC endpoints")
	} else {
		uses = uses.Union(NewCapabilitySet(CapIPCRestrict))
	}

	switch s.Net {
	case NetDisable:
		flags = append(flags, "--network=none")
		uses = uses.Union(NewCapabilitySet(CapNetDisable))
	case NetEnable:
		flags = append(flags, "--network=sandbox")
		uses = uses.Union(NewCapabilitySet(CapNetEnable))
	case NetOutbound:
		uses = uses.Union(NewCapabilitySet(CapNetOutbound))
		caveats = append(caveats, netOutboundExfiltrationCaveat,
			"gvisor net.outbound denies TCP listen/accept/accept4; UDP bind may still be creatable, and the syscall-wide deny also blocks AF_UNIX stream servers")
	}

	if len(s.Readable) > 0 {
		if !preloadFallback {
			uses = uses.Union(NewCapabilitySet(CapFSReadScope))
		}
		if needsOCI {
			caveats = append(caveats,
				"gvisor fs.read.scope additionally exposes /lib, /usr/lib, /lib64, /usr/lib64, the dynamic linker, and /etc/ld.so.* read-only so dynamic ELFs can start; this is wider than the explicit allowlist")
		}
	} else {
		uses = uses.Union(NewCapabilitySet(CapFSReadHost))
	}
	if len(s.ReadDeny) > 0 {
		if !preloadFallback {
			uses = uses.Union(NewCapabilitySet(CapFSReadDeny))
		}
		caveats = append(caveats,
			"gvisor read-deny obscures existing denied paths with empty bind mounts; nonexistent denied paths cannot be pre-mounted in broad-read mode without touching the host")
		caveats = append(caveats,
			"gvisor read-deny overmounts denied paths by path; a hardlink or alternate mount path to a denied file still reads the original inode and bypasses the denial")
	}

	switch s.Write {
	case WriteNone:
		// runsc do is read-only by default; nothing to add.
		uses = uses.Union(NewCapabilitySet(CapFSWriteDeny))
	case WriteEphemeral:
		flags = append(flags, "--overlay2=all:memory")
		uses = uses.Union(NewCapabilitySet(CapFSWriteEphemeral))
		caveats = append(caveats,
			"gvisor overlay flag syntax varies by runsc version (used --overlay2=all:memory)")
		caveats = append(caveats,
			"gvisor memory overlays keep non-persistent writes off host disk, but behavior can vary by runsc overlay mode/version")
	case WriteScope:
		if !preloadFallback {
			uses = uses.Union(NewCapabilitySet(CapFSWriteScope))
		}
		caveats = append(caveats, "gvisor scoped writes are path/mount based; hardlinks or nested host mountpoints under writable paths can affect host objects outside the lexical scope")
		caveats = append(caveats, diskQuotaCaveat)
	case WriteOverlay:
		flags = append(flags, "--overlay2=root:memory")
		if !preloadFallback {
			uses = uses.Union(NewCapabilitySet(CapFSWriteScope, CapFSWriteEphemeral))
		}
		caveats = append(caveats,
			"gvisor overlay flag syntax varies by runsc version (used --overlay2=root:memory)")
		caveats = append(caveats, "gvisor scoped writes are path/mount based; hardlinks or nested host mountpoints under writable paths can affect host objects outside the lexical scope")
		caveats = append(caveats, diskQuotaCaveat)
		caveats = append(caveats,
			"gvisor memory overlays keep outside-bind writes off host disk, but writable bind mounts still consume host disk and runsc overlay behavior can vary by mode/version")
	}

	if s.NoExec {
		uses = uses.Union(NewCapabilitySet(CapProcNoExec))
	}
	if s.CPUs > 0 {
		uses = uses.Union(NewCapabilitySet(CapResCPU))
		caveats = append(caveats,
			"gvisor CPU limit is applied to the sandbox's host cgroup via runsc; enforcement requires cgroup support on the host, and requests at least the host logical CPU count impose no effective limit")
	}
	if s.MemoryBytes > 0 {
		uses = uses.Union(NewCapabilitySet(CapResMemory))
		caveats = append(caveats,
			"gvisor memory and swap limits are charged to the sandbox's host cgroup via runsc; enforcement requires cgroup support on the host")
	}
	if s.PIDs > 0 {
		uses = uses.Union(NewCapabilitySet(CapResPIDs))
		caveats = append(caveats,
			"gvisor process-count limit is applied to the sandbox's host cgroup via runsc; enforcement requires pids cgroup support on the host")
	}
	if envScrubActive(s) {
		uses = uses.Union(NewCapabilitySet(CapEnvScrub))
	}

	if os.Getenv("ISOBOX_RUNSC") != "" {
		caveats = append(caveats, "kernel.isolation assumes ISOBOX_RUNSC points at a genuine gVisor runsc; a non-gVisor runtime would run on the host kernel without userspace-kernel isolation")
	}

	if needsOCI {
		if s.Net == NetEnable {
			caveats = append(caveats,
				"gvisor net.enable allows egress and in-sandbox listeners; there is no host-publish/DNAT for external hosts, but the host shares the point-to-point veth link and can reach the sandbox's listeners directly. Use --net=outbound to deny inbound")
		}
		gv := newGvisorOCIPlan(s)
		gv.RuntimeFlags = append([]string(nil), flags...)
		return &Plan{
			Backend: BackendGvisor,
			Argv:    gvisorOCIArgv(gv),
			Uses:    uses,
			Caveats: caveats,
			gv:      gv,
			fs:      fs,
		}, nil
	}

	argv := append([]string{gvisorBinary}, flags...)
	argv = append(argv, "do")
	// Insert a "--" terminator so a command whose argv starts with a token that
	// looks like a `runsc do` flag (e.g. --network=host, --force-overlay=false)
	// is treated as the command, not parsed by runsc — which would defeat
	// net.disable / fs.write.deny.
	argv = append(argv, "--")
	argv = append(argv, s.Args...)

	return &Plan{
		Backend: BackendGvisor,
		Argv:    argv,
		Uses:    uses,
		Caveats: caveats,
		fs:      fs,
	}, nil
}
