package isobox

import (
	"fmt"
	"path/filepath"
	"strings"
)

// NetMode controls network access. The zero value denies external/non-local access.
type NetMode int

const (
	// NetDisable blocks external/non-local network access. Zero value.
	NetDisable NetMode = iota
	// NetEnable permits network access.
	NetEnable
	// NetOutbound permits outbound connections only (no listening/inbound).
	NetOutbound
)

func (n NetMode) String() string {
	switch n {
	case NetDisable:
		return "disable"
	case NetEnable:
		return "enable"
	case NetOutbound:
		return "outbound"
	default:
		return fmt.Sprintf("NetMode(%d)", int(n))
	}
}

// WriteMode controls filesystem writes. The zero value denies all writes.
type WriteMode int

const (
	// WriteNone denies every write to the host filesystem. Zero value.
	WriteNone WriteMode = iota
	// WriteScope permits writes under Spec.Writable and optional temp roots.
	WriteScope
	// WriteEphemeral permits backend-provided ephemeral writes; backend scope and
	// coverage are surfaced as caveats.
	WriteEphemeral
	// WriteOverlay persists writes under Spec.Writable and optional temp roots,
	// while writes elsewhere are ephemeral when the backend can provide an
	// overlay/shadow filesystem and denied otherwise.
	WriteOverlay
)

func (w WriteMode) String() string {
	switch w {
	case WriteNone:
		return "none"
	case WriteScope:
		return "scope"
	case WriteEphemeral:
		return "ephemeral"
	case WriteOverlay:
		return "overlay"
	default:
		return fmt.Sprintf("WriteMode(%d)", int(w))
	}
}

// Spec is a backend-independent description of a confined command. Backends do
// not share the same capability set, so non-portable choices are reported as
// caveats, or rejected outright when Strict is set.
type Spec struct {
	// Args is the command and its arguments. Args[0] is the executable.
	Args []string
	// Dir is the working directory for the command. Empty inherits the caller's.
	Dir string
	// Env is the environment as KEY=VALUE entries. Nil inherits the caller's.
	Env []string

	// Net selects the network policy.
	Net NetMode
	// Write selects the filesystem write policy.
	Write WriteMode
	// Writable lists paths the sandbox may write when Write == WriteScope or
	// Write == WriteOverlay.
	Writable []string
	// Readable, when non-empty, restricts host/user filesystem reads to these
	// paths plus backend-required runtime paths and ambient OS grants surfaced in
	// plan caveats. Empty grants broad host reads where the backend supports it.
	Readable []string
	// ReadDeny lists sensitive paths to carve out of broad/scoped reads when a
	// backend supports read deny rules.
	ReadDeny []string
	// NoExec forbids creating a new program image after the initial command
	// starts. It does not forbid fork/clone without exec.
	NoExec bool
	// AllowTemp additionally permits writes to the OS temp dir when
	// Write == WriteScope or Write == WriteOverlay. Many tools need a writable
	// temp; it is opt-in except profiles may enable it.
	AllowTemp bool

	// MachAllow lists Mach service global-names the sandbox may look up despite
	// the default Mach-lookup denial. It is a Seatbelt-only allowance
	// (mach.restrict); other backends ignore it with a caveat. Use it
	// for macOS programs that need directory services — for example
	// "com.apple.system.opendirectoryd.libinfo" so getpwnam-based user lookup
	// resolves names instead of falling back to raw uids.
	// Independent of this list, when Net permits the network Seatbelt also
	// re-allows the Apple TLS trust services (trustd/securityd) so
	// Security.framework certificate validation works; see the Net docs.
	MachAllow []string

	// CPUs limits CPU usage to this many logical cores; fractional values are
	// allowed (1.5 = one and a half cores). Zero means no CPU limit. Backends
	// that cannot cap CPU report a caveat (and Strict rejects it).
	CPUs float64
	// MemoryBytes limits the sandbox's memory footprint, in bytes. Zero means
	// no memory limit. Backends that cannot cap memory report a caveat (and
	// Strict rejects it).
	MemoryBytes int64

	// Strict rejects any capability outside Intersection(), guaranteeing
	// identical enforcement across backends instead of degrading per platform.
	Strict bool
}

// Capabilities returns the capability set this spec requests.
func (s Spec) Capabilities() CapabilitySet {
	caps := NewCapabilitySet()
	switch s.Net {
	case NetDisable:
		caps = caps.Union(NewCapabilitySet(CapNetDisable))
	case NetEnable:
		caps = caps.Union(NewCapabilitySet(CapNetEnable))
	case NetOutbound:
		caps = caps.Union(NewCapabilitySet(CapNetOutbound))
	}
	switch s.Write {
	case WriteNone:
		caps = caps.Union(NewCapabilitySet(CapFSWriteDeny))
	case WriteScope:
		caps = caps.Union(NewCapabilitySet(CapFSWriteScope))
	case WriteEphemeral:
		caps = caps.Union(NewCapabilitySet(CapFSWriteEphemeral))
	case WriteOverlay:
		caps = caps.Union(NewCapabilitySet(CapFSWriteScope, CapFSWriteEphemeral))
	}
	if len(s.Readable) > 0 {
		caps = caps.Union(NewCapabilitySet(CapFSReadScope))
	} else {
		caps = caps.Union(NewCapabilitySet(CapFSReadHost))
	}
	if len(s.ReadDeny) > 0 {
		caps = caps.Union(NewCapabilitySet(CapFSReadDeny))
	}
	if s.NoExec {
		caps = caps.Union(NewCapabilitySet(CapProcNoExec))
	}
	if len(s.MachAllow) > 0 {
		caps = caps.Union(NewCapabilitySet(CapMachRestrict))
	}
	if s.CPUs > 0 {
		caps = caps.Union(NewCapabilitySet(CapResCPU))
	}
	if s.MemoryBytes > 0 {
		caps = caps.Union(NewCapabilitySet(CapResMemory))
	}
	return caps
}

// validate checks the spec is well-formed and, when Strict, portable.
func (s Spec) validate() error {
	if len(s.Args) == 0 {
		return fmt.Errorf("isobox: spec has no command (Args is empty)")
	}
	if s.Args[0] == "" {
		return fmt.Errorf("isobox: spec executable (Args[0]) is empty")
	}
	if err := validatePathList("Readable", s.Readable); err != nil {
		return err
	}
	if err := validatePathList("ReadDeny", s.ReadDeny); err != nil {
		return err
	}
	if err := validatePathList("Writable", s.Writable); err != nil {
		return err
	}
	if s.AllowTemp && s.Write != WriteScope && s.Write != WriteOverlay {
		return fmt.Errorf("isobox: AllowTemp requires Write=scope or Write=overlay")
	}
	if len(s.Writable) > 0 && s.Write != WriteScope && s.Write != WriteOverlay {
		return fmt.Errorf("isobox: Writable paths require Write=scope or Write=overlay")
	}
	if s.Write == WriteScope && len(s.Writable) == 0 && !s.AllowTemp {
		return fmt.Errorf("isobox: Write=scope but no Writable paths and AllowTemp is false; use Write=none instead")
	}
	if s.CPUs < 0 {
		return fmt.Errorf("isobox: CPUs must not be negative")
	}
	if s.MemoryBytes < 0 {
		return fmt.Errorf("isobox: MemoryBytes must not be negative")
	}
	if len(s.Readable) > 0 && s.Dir != "" {
		dir := canonPath(s.Dir)
		if !pathUnderAnyScope(dir, s.Readable) && !pathUnderAnyScope(dir, s.Writable) {
			return fmt.Errorf("isobox: Dir %q must be under a Readable or Writable path when Readable is set", s.Dir)
		}
	}
	if s.Strict {
		extra := s.Capabilities().Sub(Intersection())
		if extra.Len() > 0 {
			names := make([]string, 0, extra.Len())
			for _, c := range extra.List() {
				names = append(names, string(c))
			}
			return fmt.Errorf("isobox: Strict spec uses non-portable capabilities: %s", strings.Join(names, ", "))
		}
	}
	return nil
}

func validatePathList(field string, paths []string) error {
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("isobox: %s contains a blank path", field)
		}
	}
	return nil
}

func pathUnderAnyScope(path string, scopes []string) bool {
	for _, scope := range scopes {
		if pathUnderScope(path, canonPath(scope)) {
			return true
		}
	}
	return false
}

func pathUnderScope(path, scope string) bool {
	path = filepath.Clean(path)
	scope = filepath.Clean(scope)
	if path == scope {
		return true
	}
	if scope == string(filepath.Separator) {
		return strings.HasPrefix(path, string(filepath.Separator))
	}
	return strings.HasPrefix(path, scope+string(filepath.Separator))
}

// Plan is the compiled, inspectable result of preparing a Spec for a backend.
// It is produced without running anything, so it can be unit-tested and shown
// to the user before execution.
type Plan struct {
	// Backend is the implementation that will run the command.
	Backend Backend
	// Argv is the exact process isobox will exec (e.g. sandbox-exec ... or runsc ...).
	Argv []string
	// Profile is the generated Seatbelt SBPL profile, AppContainer preview text,
	// or "" for backends that only have argv.
	Profile string
	// Uses is the set of capabilities this plan actually exercises.
	Uses CapabilitySet
	// Caveats records where the active backend deviates from the spec's intent
	// (degraded or differently-enforced semantics). Empty means a faithful match.
	Caveats []string
	// ac carries the structured AppContainer profile for the Windows executor.
	ac *acProfile
	// gv carries an optional structured gVisor OCI plan for the gVisor executor.
	gv *gvisorOCIPlan
	// docker carries optional Docker runner metadata.
	docker *dockerPlan
	// fs carries an optional structured filesystem virtualization plan.
	fs *fsVirtualizationPlan
	// resources carries optional best-effort resource watchdog settings.
	resources *resourceWatchdogPlan
}

// FilesystemVirtualization returns the planned filesystem virtualization
// mechanism, or "" when the plan uses no extra filesystem layer.
func (p *Plan) FilesystemVirtualization() string {
	if p == nil || p.fs == nil {
		return ""
	}
	return string(p.fs.Kind)
}
