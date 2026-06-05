// Package isobox runs a command inside the host's native sandbox, behind one
// interface. On macOS it compiles to a Seatbelt (sandbox-exec) profile; on
// Linux it compiles to a gVisor (runsc) invocation; on Windows it launches
// directly inside an AppContainer.
//
// The backends do not enforce the same things. isobox models this explicitly as
// a capability set per backend, so callers can target either the portable
// Intersection (behaves identically everywhere) or opt into a backend's Union
// extras and accept documented, queryable caveats.
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
	// BackendDockerEphemeral is Docker run --rm with no host mounts and a
	// disposable, read-only container filesystem plus tmpfs scratch.
	BackendDockerEphemeral Backend = "docker-ephemeral"
)

// Capability is a single, named sandboxing guarantee. A backend either supports
// it or it does not; this is what Union and Intersection are computed over.
type Capability string

const (
	// CapNetDisable denies external/non-local network access.
	CapNetDisable Capability = "net.disable"
	// CapNetEnable permits network access.
	CapNetEnable Capability = "net.enable"
	// CapNetOutbound permits outbound connections but blocks listening/inbound.
	CapNetOutbound Capability = "net.outbound"
	// CapFSReadHost grants broad read access to the host filesystem.
	CapFSReadHost Capability = "fs.read.host"
	// CapFSReadScope restricts reads to an explicit allowlist.
	CapFSReadScope Capability = "fs.read.scope"
	// CapFSReadDeny grants broad reads while denying listed sensitive paths.
	CapFSReadDeny Capability = "fs.read.deny"
	// CapFSWriteDeny denies all writes to the host filesystem.
	CapFSWriteDeny Capability = "fs.write.deny"
	// CapFSWriteScope permits writes only to listed paths, persisting to the host.
	CapFSWriteScope Capability = "fs.write.scope"
	// CapFSWriteEphemeral permits writes while arranging for them to be
	// discarded; the host filesystem is never modified.
	CapFSWriteEphemeral Capability = "fs.write.ephemeral"
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
)

// capDescriptions documents every capability isobox knows about.
var capDescriptions = map[Capability]string{
	CapNetDisable:       "deny network access; some backends additionally block loopback (see caveats)",
	CapNetEnable:        "permit network access",
	CapNetOutbound:      "permit outbound connections, block inbound/listen",
	CapFSReadHost:       "read the host filesystem broadly",
	CapFSReadScope:      "restrict reads to an allowlist",
	CapFSReadDeny:       "read broadly except denied sensitive paths",
	CapFSWriteDeny:      "deny all writes to the host filesystem",
	CapFSWriteScope:     "permit writes only to listed paths, persisted to host",
	CapFSWriteEphemeral: "permit writes but discard them; host untouched",
	CapProcNoExec:       "forbid executing another program image",
	CapKernelIsolation:  "serve syscalls from a user-space kernel; shield host kernel",
	CapIPCRestrict:      "no host local IPC endpoint reachable",
	CapMachRestrict:     "restrict Mach service lookups (Seatbelt-only)",
	CapResCPU:           "limit CPU usage to a fraction of the host's cores",
	CapResMemory:        "limit the sandbox's memory footprint",
}

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
		CapMachRestrict,
	),
	BackendGvisor: NewCapabilitySet(
		CapNetDisable, CapNetEnable, CapNetOutbound,
		CapFSReadHost, CapFSReadScope, CapFSReadDeny,
		CapFSWriteDeny, CapFSWriteScope, CapFSWriteEphemeral,
		CapProcNoExec,
		CapKernelIsolation, CapIPCRestrict,
		CapResCPU, CapResMemory,
	),
	BackendAppContainer: NewCapabilitySet(
		CapNetDisable, CapNetEnable,
		CapFSReadScope,
		CapFSWriteScope,
		CapProcNoExec,
		CapResCPU, CapResMemory,
	),
	BackendDockerEphemeral: NewCapabilitySet(
		CapNetDisable, CapNetEnable,
		CapResCPU, CapResMemory,
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

// Intersection returns capabilities supported by every backend. A spec built
// only from these behaves identically on all platforms.
func Intersection() CapabilitySet {
	bs := Backends()
	if len(bs) == 0 {
		return NewCapabilitySet()
	}
	out := CapsOf(bs[0])
	for _, b := range bs[1:] {
		out = out.Intersect(backendCaps[b])
	}
	return out
}
