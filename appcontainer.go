package isobox

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// acCapabilitySID is the numeric WELL_KNOWN_SID_TYPE for a Windows capability
// SID. Keeping it as plain data lets the AppContainer compiler stay portable;
// the Windows executor casts it to windows.WELL_KNOWN_SID_TYPE.
type acCapabilitySID uint32

const (
	acWinCapabilityInternetClientSid             acCapabilitySID = 85
	acWinCapabilityInternetClientServerSid       acCapabilitySID = 86
	acWinCapabilityPrivateNetworkClientServerSid acCapabilitySID = 87
)

func (s acCapabilitySID) String() string {
	switch s {
	case acWinCapabilityInternetClientSid:
		return "WinCapabilityInternetClientSid"
	case acWinCapabilityInternetClientServerSid:
		return "WinCapabilityInternetClientServerSid"
	case acWinCapabilityPrivateNetworkClientServerSid:
		return "WinCapabilityPrivateNetworkClientServerSid"
	default:
		return fmt.Sprintf("WELL_KNOWN_SID_TYPE(%d)", uint32(s))
	}
}

// acProfile is the structured AppContainer plan consumed by the Windows
// executor. It mirrors Plan.Profile, but without reparsing human-facing text.
type acProfile struct {
	ProfileName      string
	Exe              string
	WorkDir          string
	Argv             []string
	CapabilitySIDs   []acCapabilitySID
	ReadGrants       []string
	ReadDeny         []string
	WriteGrants      []string
	DeriveOnlyLowbox bool
	LPAC             bool
	ChildRestricted  bool
	CPUs             float64
	MemoryBytes      int64
}

// compileAppContainer turns a Spec into a Windows AppContainer plan. It is pure:
// it chooses capability SIDs, filesystem grants and preview text, but runs no
// Win32 calls.
func compileAppContainer(s Spec) (*Plan, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	uses := NewCapabilitySet()
	var caveats []string
	if len(s.MachAllow) > 0 {
		caveats = append(caveats, "Mach service allow-list is macOS Seatbelt-only; ignored on appcontainer")
	}
	readDeny := make([]string, 0, len(s.ReadDeny))
	for _, path := range s.ReadDeny {
		readDeny = appendGrant(readDeny, canonPath(path))
	}
	var capSIDs []acCapabilitySID

	switch s.Net {
	case NetDisable:
		uses = uses.Union(NewCapabilitySet(CapNetDisable))
		caveats = append(caveats,
			"appcontainer blocks loopback in addition to external network access")
	case NetEnable:
		capSIDs = append(capSIDs,
			acWinCapabilityInternetClientServerSid,
			acWinCapabilityPrivateNetworkClientServerSid,
		)
		uses = uses.Union(NewCapabilitySet(CapNetEnable))
	case NetOutbound:
		capSIDs = append(capSIDs, acWinCapabilityInternetClientSid)
		uses = uses.Union(NewCapabilitySet(CapNetOutbound))
		caveats = append(caveats,
			"appcontainer net.outbound is limited to InternetClient; private-network outbound is denied to keep server/listen blocked")
	}

	lpac := true
	if len(capSIDs) == 0 {
		uses = uses.Union(NewCapabilitySet(CapIPCRestrict))
	} else {
		caveats = append(caveats, "appcontainer runs as LPAC for IPC isolation, but network capability SIDs can reach host IPC endpoints that explicitly grant those capabilities; ipc.restrict is not claimed for this plan")
	}

	exe := s.Args[0]
	if resolved, ok := resolveExec(s.Args[0]); ok {
		exe = resolved
	} else {
		caveats = append(caveats,
			fmt.Sprintf("appcontainer could not resolve executable %q at compile time; launch requires it to resolve on Windows", s.Args[0]))
	}

	readableScopes := make([]string, 0, len(s.Readable))
	for _, r := range s.Readable {
		readableScopes = append(readableScopes, canonPath(r))
	}
	writableScopes := make([]string, 0, len(s.Writable))
	for _, w := range s.Writable {
		writableScopes = append(writableScopes, canonPath(w))
	}

	workDir := s.Dir
	if workDir == "" && len(readableScopes) == 0 {
		if wd, err := os.Getwd(); err == nil {
			workDir = wd
		}
	}
	if workDir != "" {
		workDir = canonPath(workDir)
	}
	if s.Write == WriteEphemeral {
		workDir = isoboxEphemeralRootPlaceholder
	}

	readGrants := make([]string, 0, len(readableScopes)+2)
	readGrants = appendGrant(readGrants, exe)
	if workDir != "" && (len(readableScopes) == 0 || pathCoveredByAnyGrant(workDir, readableScopes) || pathCoveredByAnyGrant(workDir, writableScopes)) {
		readGrants = appendGrant(readGrants, workDir)
	}
	if s.Write == WriteEphemeral {
		readGrants = appendGrant(readGrants, isoboxEphemeralRootPlaceholder)
	}
	if len(readableScopes) > 0 {
		for _, r := range readableScopes {
			readGrants = appendGrant(readGrants, r)
		}
		uses = uses.Union(NewCapabilitySet(CapFSReadScope))
		caveats = append(caveats,
			"appcontainer read grants are additive ACLs and cannot revoke ambient access; files already readable by the ALL APPLICATION PACKAGES ACE (e.g. much of %WinDir% and %ProgramFiles%) remain readable outside the readable allowlist")
	} else {
		caveats = append(caveats,
			"appcontainer broad host reads are not provided without explicit readable ACL grants")
	}
	if len(readDeny) > 0 {
		caveats = append(caveats, "appcontainer applies temporary DENY ACEs for ReadDeny paths where the DACL is writable; this is path ACL mutation, not broad read-deny capability")
	}

	writeGrants := []string(nil)
	deriveOnlyLowbox := false
	appendTempGrants := func() {
		for _, t := range osTempRoots() {
			writeGrants = appendGrant(writeGrants, t)
		}
	}
	switch s.Write {
	case WriteNone:
		deriveOnlyLowbox = true
		uses = uses.Union(NewCapabilitySet(CapFSWriteDeny))
		caveats = append(caveats, appContainerWriteDenyCaveat)
	case WriteScope:
		deriveOnlyLowbox = true
		writeGrants = make([]string, 0, len(writableScopes)+2)
		for _, w := range writableScopes {
			writeGrants = appendGrant(writeGrants, w)
		}
		if s.AllowTemp {
			appendTempGrants()
		}
		uses = uses.Union(NewCapabilitySet(CapFSWriteScope))
		caveats = append(caveats,
			"appcontainer scoped writes temporarily grant ACL access to the AppContainer SID; unclean exits can leave the grant behind")
		caveats = append(caveats, "appcontainer scoped write grants are path ACL based; hardlinks inside writable paths can modify the same file object through out-of-scope aliases")
		caveats = append(caveats, appContainerAmbientWriteCaveat)
	case WriteEphemeral:
		deriveOnlyLowbox = true
		writeGrants = appendGrant(writeGrants, isoboxEphemeralRootPlaceholder)
		uses = uses.Union(NewCapabilitySet(CapFSWriteEphemeral))
		caveats = append(caveats,
			"appcontainer ephemeral writes are workspace-scoped to Spec.Dir/cwd via a recursive temp copy that is deleted on exit")
		caveats = append(caveats,
			"appcontainer workspace copy is a full byte copy on Windows, not a reflink/CoW clone")
		caveats = append(caveats, appContainerAmbientWriteCaveat)
	case WriteOverlay:
		deriveOnlyLowbox = true
		writeGrants = make([]string, 0, len(writableScopes)+2)
		for _, w := range writableScopes {
			writeGrants = appendGrant(writeGrants, w)
		}
		if s.AllowTemp {
			appendTempGrants()
		}
		uses = uses.Union(NewCapabilitySet(CapFSWriteScope))
		caveats = append(caveats,
			"appcontainer has no ephemeral/shadow overlay; writes outside writable paths are denied")
		caveats = append(caveats,
			"appcontainer scoped writes temporarily grant ACL access to the AppContainer SID; unclean exits can leave the grant behind")
		caveats = append(caveats, "appcontainer scoped write grants are path ACL based; hardlinks inside writable paths can modify the same file object through out-of-scope aliases")
		caveats = append(caveats, appContainerAmbientWriteCaveat)
	}

	childRestricted := false
	if s.NoExec {
		childRestricted = true
		uses = uses.Union(NewCapabilitySet(CapProcNoExec))
		caveats = append(caveats, appContainerNoExecCaveat)
	}
	if s.CPUs > 0 {
		uses = uses.Union(NewCapabilitySet(CapResCPU))
		caveats = append(caveats, "appcontainer CPU limit is a job-object hard cap scheduled as a share of all host logical processors; requesting at least the host core count imposes no effective limit")
	}
	if s.MemoryBytes > 0 {
		uses = uses.Union(NewCapabilitySet(CapResMemory))
		caveats = append(caveats, "appcontainer memory limit is a job-object whole-job commit cap; exceeding it fails allocations rather than killing the process immediately; file-backed/shared mappings and working-set growth are not counted toward the commit cap, so physical footprint can exceed the requested limit")
	}

	var fs *fsVirtualizationPlan
	if s.Write == WriteEphemeral {
		fs = &fsVirtualizationPlan{Kind: fsVirtualizationWindowsWorkspaceCopy}
	}

	argv := append([]string{exe}, s.Args[1:]...)
	profile := &acProfile{
		ProfileName:      appContainerProfileName(),
		Exe:              exe,
		WorkDir:          workDir,
		Argv:             argv,
		CapabilitySIDs:   append([]acCapabilitySID(nil), capSIDs...),
		ReadGrants:       append([]string(nil), readGrants...),
		ReadDeny:         append([]string(nil), readDeny...),
		WriteGrants:      append([]string(nil), writeGrants...),
		DeriveOnlyLowbox: deriveOnlyLowbox,
		LPAC:             lpac,
		ChildRestricted:  childRestricted,
		CPUs:             s.CPUs,
		MemoryBytes:      s.MemoryBytes,
	}

	return &Plan{
		Backend: BackendAppContainer,
		Argv:    argv,
		Profile: renderAppContainerProfile(profile),
		Uses:    uses,
		Caveats: caveats,
		ac:      profile,
		fs:      fs,
	}, nil
}

func appendGrant(grants []string, path string) []string {
	if path == "" {
		return grants
	}
	for _, existing := range grants {
		if existing == path {
			return grants
		}
	}
	return append(grants, path)
}

func pathCoveredByAnyGrant(path string, grants []string) bool {
	for _, grant := range grants {
		if pathCoveredByGrant(path, grant) {
			return true
		}
	}
	return false
}

func pathCoveredByGrant(path, grant string) bool {
	if strings.EqualFold(path, grant) {
		return true
	}
	grant = strings.TrimRight(grant, `/\`)
	if grant == "" {
		return false
	}
	if len(path) <= len(grant) || !strings.EqualFold(path[:len(grant)], grant) {
		return false
	}
	return path[len(grant)] == '/' || path[len(grant)] == '\\'
}

// appContainerProfileName returns a per-run unique AppContainer profile name.
// The name is "isobox-" + 16 hex chars from crypto/rand. Per-run uniqueness keeps
// stale ACEs from prior aborted runs out of the new sandbox: each run gets a
// fresh AppContainer SID, ACL grants are bounded to that SID, and the profile
// is deleted unconditionally on exit. See R6.
func appContainerProfileName() string {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		// crypto/rand failure is exceptional; fall back to a process-unique
		// suffix so two concurrent compiles still produce distinct names.
		return fmt.Sprintf("isobox-%016x", uint64(os.Getpid())<<32^appContainerNameCounter.next())
	}
	return "isobox-" + hex.EncodeToString(b[:])
}

// appContainerNameCounter is the fallback monotonic source used only when
// crypto/rand fails. Plain int incremented under a mutex; not security-relevant.
var appContainerNameCounter = &acNameCounter{}

type acNameCounter struct {
	mu sync.Mutex
	n  uint64
}

func (c *acNameCounter) next() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return c.n
}

const appContainerWriteDenyCaveat = "appcontainer WriteNone uses a derive-only lowbox with no per-profile storage grant; host paths remain writable if they already grant write access to ALL APPLICATION PACKAGES"
const appContainerAmbientWriteCaveat = "appcontainer derive-only lowbox avoids per-profile storage, but cannot revoke ambient write access already granted to ALL APPLICATION PACKAGES"

const appContainerNoExecCaveat = "appcontainer enforces no-exec via PROCESS_CREATION_CHILD_PROCESS_RESTRICTED, which is stricter than the isobox contract: ALL child-process creation (including fork-like CreateProcess for the same image) is blocked, not just exec of a new image; it does not stop a process created on the sandbox's behalf by a reachable out-of-process broker (COM/RPC/WinRT activation), which runs outside the restriction"

func renderAppContainerProfile(p *acProfile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "appcontainer %s\n", p.ProfileName)
	fmt.Fprintf(&b, "  exe: %s\n", p.Exe)
	if p.WorkDir != "" {
		fmt.Fprintf(&b, "  workdir: %s\n", p.WorkDir)
	}
	b.WriteString("  capabilities:")
	if len(p.CapabilitySIDs) == 0 {
		b.WriteString(" none")
	} else {
		for _, sid := range p.CapabilitySIDs {
			fmt.Fprintf(&b, " %s", sid)
		}
	}
	b.WriteByte('\n')
	if p.DeriveOnlyLowbox {
		b.WriteString("  profile storage: derive-only\n")
	}
	if p.LPAC {
		b.WriteString("  all application packages: opt-out\n")
	}
	b.WriteString("  read grants:")
	if len(p.ReadGrants) == 0 {
		b.WriteString(" none")
	} else {
		for _, path := range p.ReadGrants {
			fmt.Fprintf(&b, " %s", path)
		}
	}
	b.WriteByte('\n')
	b.WriteString("  read deny:")
	if len(p.ReadDeny) == 0 {
		b.WriteString(" none")
	} else {
		for _, path := range p.ReadDeny {
			fmt.Fprintf(&b, " %s", path)
		}
	}
	b.WriteByte('\n')
	b.WriteString("  write grants:")
	if len(p.WriteGrants) == 0 {
		b.WriteString(" none")
	} else {
		for _, path := range p.WriteGrants {
			fmt.Fprintf(&b, " %s", path)
		}
	}
	b.WriteByte('\n')
	fmt.Fprintf(&b, "  child process policy: %s\n", appContainerChildPolicy(p.ChildRestricted))
	if p.CPUs > 0 {
		fmt.Fprintf(&b, "  cpu limit: %s cores\n", strconv.FormatFloat(p.CPUs, 'f', -1, 64))
	}
	if p.MemoryBytes > 0 {
		fmt.Fprintf(&b, "  memory limit: %d bytes\n", p.MemoryBytes)
	}
	return b.String()
}

func appContainerChildPolicy(restricted bool) string {
	if restricted {
		return "restricted"
	}
	return "default"
}

// cpuRateMaxHundredths is the Windows job-object CpuRate value that represents
// 100% of all host logical processors (a percentage in hundredths of a percent).
const cpuRateMaxHundredths = 10000

// cpuRateHundredths converts a logical-core count into a Windows job-object
// CpuRate hard cap: a share of all host processors expressed in hundredths of
// a percent (1..10000). Asking for at least the host core count yields 100%.
// It lives in the portable file so the conversion is unit-testable off Windows.
func cpuRateHundredths(cpus float64) uint32 {
	n := float64(runtime.NumCPU())
	if n <= 0 {
		n = 1
	}
	rate := int64(cpus/n*cpuRateMaxHundredths + 0.5)
	if rate < 1 {
		rate = 1
	}
	if rate > cpuRateMaxHundredths {
		rate = cpuRateMaxHundredths
	}
	return uint32(rate)
}
