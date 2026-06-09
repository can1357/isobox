// Package isobox runs a command inside the host's native sandbox, behind one
// interface. On macOS it compiles to a Seatbelt (sandbox-exec) profile; on
// Linux it compiles to a gVisor (runsc) invocation; on Windows it launches
// directly inside an AppContainer.
//
// The backends do not enforce the same things. isobox models this explicitly as
// Intersection (every backend has an enforcement strategy) or opt into a
// backend's Union extras and accept documented, queryable caveats.
package isobox

import "sort"

// Backend identifies a sandbox implementation.
type Backend string

const (
	// BackendSeatbelt is macOS Seatbelt via sandbox-exec.
	BackendSeatbelt Backend = "seatbelt"
	// BackendGvisor is Linux gVisor via runsc.
	BackendGvisor Backend = "gvisor"
	// BackendAppContainer is Windows AppContainer via in-process Win32 calls.
	BackendAppContainer Backend = "appcontainer"
	// BackendDockerEphemeral is Docker run --rm using the configured image,
	// private IPC, no host mounts unless explicitly scoped, and disposable Docker
	// storage/tmpfs for backend scratch.
	BackendDockerEphemeral Backend = "docker-ephemeral"
	// BackendDockerRunscEphemeral is Docker run --rm with the gVisor runsc
	// runtime forced and verified at launch.
	BackendDockerRunscEphemeral Backend = "docker-runsc-ephemeral"
)

// Capability is a single, named sandboxing guarantee. A backend either supports
// it or it does not; this is what Union and Intersection are computed over.
type Capability string

const (
	// CapNetDisable denies external/non-local network access.
	CapNetDisable Capability = "net.disable"
	// CapNetEnable permits network access.
	CapNetEnable Capability = "net.enable"
	// CapNetOutbound permits outbound connections and blocks TCP server setup.
	// It is not an egress filter; allowed outbound connections can exfiltrate
	// data unless the caller or surrounding network constrains them.
	CapNetOutbound Capability = "net.outbound"
	// CapFSReadHost grants broad read access to the host filesystem.
	CapFSReadHost Capability = "fs.read.host"
	// CapFSReadScope restricts host/user filesystem reads to an explicit
	// allowlist plus backend-required runtime paths and ambient OS grants surfaced
	// as caveats.
	CapFSReadScope Capability = "fs.read.scope"
	// CapFSReadDeny grants broad reads while denying listed sensitive paths.
	CapFSReadDeny Capability = "fs.read.deny"
	// CapFSWriteDeny denies all writes to the host filesystem.
	CapFSWriteDeny Capability = "fs.write.deny"
	// CapFSWriteScope permits writes under listed paths, plus opt-in temp roots;
	// listed-path writes persist to the host.
	CapFSWriteScope Capability = "fs.write.scope"
	// CapFSWriteEphemeral permits backend-provided ephemeral writes; configured
	// host inputs are not modified, and backend scope/coverage is surfaced in
	// caveats.
	CapFSWriteEphemeral Capability = "fs.write.ephemeral"
	// CapEnvScrub removes selected environment variables before process launch.
	CapEnvScrub Capability = "env.scrub"
	// CapProcNoExec forbids creating a new program image after launch.
	CapProcNoExec Capability = "proc.no_exec"
	// CapKernelIsolation serves syscalls from a user-space kernel, shielding the
	// host kernel from the sandboxed process (reduced kernel attack surface).
	CapKernelIsolation Capability = "kernel.isolation"
	// CapIPCRestrict prevents access to host local IPC endpoints.
	CapIPCRestrict Capability = "ipc.restrict"
	// CapMachRestrict is a Seatbelt-only, macOS-specific Mach lookup restriction.
	CapMachRestrict Capability = "mach.restrict"
	// CapResCPU caps CPU usage at a fraction of the host's logical cores.
	CapResCPU Capability = "res.cpu"
	// CapResMemory caps the sandbox's memory footprint in bytes.
	CapResMemory Capability = "res.memory"
	// CapResPIDs caps the sandbox's process/task count.
	CapResPIDs Capability = "res.pids"
)

// capDescriptions documents every capability isobox knows about.
var capDescriptions = map[Capability]string{
	CapNetDisable:       "deny network access; some backends additionally block loopback (see caveats)",
	CapNetEnable:        "permit network access",
	CapNetOutbound:      "permit outbound connections; block inbound TCP listeners; not a domain/CIDR allowlist",
	CapFSReadHost:       "read the host filesystem broadly",
	CapFSReadScope:      "restrict host/user filesystem reads to an allowlist plus backend runtime paths",
	CapFSReadDeny:       "read broadly except denied sensitive paths",
	CapFSWriteDeny:      "deny all writes to the host filesystem",
	CapFSWriteScope:     "permit writes under listed paths plus opt-in temp roots; listed-path writes persist",
	CapFSWriteEphemeral: "permit backend ephemeral writes; configured host inputs stay untouched",
	CapEnvScrub:         "scrub inherited environment variables by name pattern before launch",
	CapProcNoExec:       "forbid executing another program image",
	CapKernelIsolation:  "serve syscalls from a user-space kernel; shield host kernel",
	CapIPCRestrict:      "no host local IPC endpoint reachable",
	CapMachRestrict:     "restrict Mach service lookups (Seatbelt-only)",
	CapResCPU:           "limit CPU usage to a fraction of the host's cores",
	CapResMemory:        "limit the sandbox's memory footprint",
	CapResPIDs:          "limit the sandbox's process/task count",
}

const netOutboundExfiltrationCaveat = "net.outbound is not an egress filter or domain/CIDR allowlist; permitted outbound connections can exfiltrate data unless the caller or surrounding network constrains them"

const diskQuotaCaveat = "isobox does not enforce res.disk; scoped/persistent writes can fill the backing host filesystem unless separately constrained"

// Describe returns a human-readable description of a capability.
func (c Capability) Describe() string { return capDescriptions[c] }

// backendCaps is the authoritative table of what each backend can enforce. It
// is plain data and identical on every host, so Union/Intersection are
// answerable regardless of which OS isobox is running on.
var backendCaps = map[Backend]CapabilitySet{
	BackendSeatbelt: NewCapabilitySet(
		CapNetDisable, CapNetEnable, CapNetOutbound,
		CapFSReadHost, CapFSReadScope, CapFSReadDeny,
		CapFSWriteDeny, CapFSWriteScope, CapFSWriteEphemeral,
		CapEnvScrub,
		CapMachRestrict,
	),
	BackendGvisor: NewCapabilitySet(
		CapNetDisable, CapNetEnable, CapNetOutbound,
		CapFSReadHost, CapFSReadScope, CapFSReadDeny,
		CapFSWriteDeny, CapFSWriteScope, CapFSWriteEphemeral,
		CapEnvScrub,
		CapProcNoExec,
		CapKernelIsolation, CapIPCRestrict,
		CapResCPU, CapResMemory, CapResPIDs,
	),
	BackendAppContainer: NewCapabilitySet(
		CapNetDisable, CapNetEnable, CapNetOutbound,
		CapFSReadScope,
		CapFSWriteDeny,
		CapFSWriteEphemeral,
		CapFSWriteScope,
		CapEnvScrub,
		CapProcNoExec,
		CapIPCRestrict,
		CapResCPU, CapResMemory, CapResPIDs,
	),
	BackendDockerEphemeral: NewCapabilitySet(
		CapNetDisable, CapNetEnable, CapNetOutbound,
		CapFSWriteDeny,
		CapFSWriteEphemeral,
		CapFSReadScope, CapFSWriteScope,
		CapEnvScrub,
		CapIPCRestrict,
		CapResCPU, CapResMemory, CapResPIDs,
	),
	BackendDockerRunscEphemeral: NewCapabilitySet(
		CapNetDisable, CapNetEnable, CapNetOutbound,
		CapFSWriteDeny,
		CapFSWriteEphemeral,
		CapFSReadScope, CapFSWriteScope,
		CapEnvScrub,
		CapIPCRestrict,
		CapKernelIsolation,
		CapResCPU, CapResMemory, CapResPIDs,
	),
}

// CapabilitySet is an unordered set of capabilities with set algebra. The zero
// value is not usable; construct with NewCapabilitySet.
type CapabilitySet struct {
	m map[Capability]struct{}
}

// NewCapabilitySet builds a set from the given capabilities.
func NewCapabilitySet(caps ...Capability) CapabilitySet {
	s := CapabilitySet{m: make(map[Capability]struct{}, len(caps))}
	for _, c := range caps {
		s.m[c] = struct{}{}
	}
	return s
}

// Has reports whether the set contains c.
func (s CapabilitySet) Has(c Capability) bool {
	_, ok := s.m[c]
	return ok
}

// Len reports the number of capabilities in the set.
func (s CapabilitySet) Len() int { return len(s.m) }

// List returns the capabilities in sorted order for stable output.
func (s CapabilitySet) List() []Capability {
	out := make([]Capability, 0, len(s.m))
	for c := range s.m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Union returns the capabilities present in either set.
func (s CapabilitySet) Union(other CapabilitySet) CapabilitySet {
	out := NewCapabilitySet(s.List()...)
	for c := range other.m {
		out.m[c] = struct{}{}
	}
	return out
}

// Intersect returns the capabilities present in both sets.
func (s CapabilitySet) Intersect(other CapabilitySet) CapabilitySet {
	out := NewCapabilitySet()
	for c := range s.m {
		if other.Has(c) {
			out.m[c] = struct{}{}
		}
	}
	return out
}

// Sub returns the capabilities in s that are absent from other.
func (s CapabilitySet) Sub(other CapabilitySet) CapabilitySet {
	out := NewCapabilitySet()
	for c := range s.m {
		if !other.Has(c) {
			out.m[c] = struct{}{}
		}
	}
	return out
}

// CapsOf returns the capability set for a backend. The returned set is a copy.
func CapsOf(b Backend) CapabilitySet {
	return NewCapabilitySet(backendCaps[b].List()...)
}

// Backends returns every backend isobox knows about, sorted.
func Backends() []Backend {
	out := make([]Backend, 0, len(backendCaps))
	for b := range backendCaps {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Union returns capabilities supported by at least one backend.
func Union() CapabilitySet {
	out := NewCapabilitySet()
	for _, b := range Backends() {
		out = out.Union(backendCaps[b])
	}
	return out
}

// Intersection returns capabilities supported by every supported host OS after
// accounting for auto-selectable compatibility backends on that OS. In other
// words, it is:
//
//	(union of macOS-compatible backends)
//	∩ (union of Linux-compatible backends)
//	∩ (union of Windows-compatible backends)
//
// A Strict spec may use these capabilities without being tied to one named
// backend, though the selected optional backend still has to exist at runtime.
func Intersection() CapabilitySet {
	oses := []string{"darwin", "linux", "windows"}
	out := NewCapabilitySet()
	for i, goos := range oses {
		union := NewCapabilitySet()
		for _, b := range backendCandidatesForGOOS(goos) {
			union = union.Union(CapsOf(b))
		}
		if i == 0 {
			out = union
			continue
		}
		out = out.Intersect(union)
	}
	return out
}
