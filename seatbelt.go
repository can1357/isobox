package isobox

import (
	"fmt"
	"strings"
)

// sbplQuote renders a path as an SBPL string literal.
func sbplQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// sbplSubpaths writes `(<verb> <op> (subpath "a") (subpath "b") ...)`.
func sbplSubpaths(b *strings.Builder, verb, op string, paths []string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintf(b, "(%s %s", verb, op)
	for _, p := range paths {
		fmt.Fprintf(b, " (subpath %s)", sbplQuote(p))
	}
	b.WriteString(")\n")
}

// sbplLiterals writes `(<verb> <op> (literal "a") (literal "b") ...)`.
func sbplLiterals(b *strings.Builder, verb, op string, paths []string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintf(b, "(%s %s", verb, op)
	for _, p := range paths {
		fmt.Fprintf(b, " (literal %s)", sbplQuote(p))
	}
	b.WriteString(")\n")
}

var (
	seatbeltDeviceReadLiterals  = []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"}
	seatbeltDeviceWriteLiterals = []string{"/dev/null"}
)

// seatbeltTLSTrustMachServices are the Apple Mach services a client needs to
// evaluate TLS certificate trust on macOS: trustd performs the evaluation and
// reads the system/admin/user trust settings, and securityd (SecurityServer)
// backs keychain access. Native-TLS stacks built on Security.framework
// (e.g. Go's crypto/x509 platform verifier, Rust's rustls-platform-verifier)
// fail with errSecNotAvailable (-25291, "No keychain is available") when these
// lookups are denied, even though raw sockets still connect. isobox re-allows
// them whenever network access is permitted so HTTPS works without a manual
// --mach-allow.
var seatbeltTLSTrustMachServices = []string{
	"com.apple.trustd",
	"com.apple.trustd.agent",
	"com.apple.SecurityServer",
}

// mergeMachServices merges the caller's MachAllow with backend-required
// services, dropping duplicates while preserving first-seen order.
func mergeMachServices(user, extra []string) []string {
	out := make([]string, 0, len(user)+len(extra))
	seen := make(map[string]struct{}, len(user)+len(extra))
	for _, group := range [2][]string{user, extra} {
		for _, name := range group {
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

const isoboxEphemeralRootPlaceholder = "<isobox-ephemeral-root>"

// compileSeatbelt turns a Spec into a Seatbelt (sandbox-exec) plan. It is pure:
// it builds the SBPL profile and argv but runs nothing.
func compileSeatbelt(s Spec) (*Plan, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	uses := NewCapabilitySet()
	var caveats []string
	var resources *resourceWatchdogPlan
	if s.CPUs > 0 || s.MemoryBytes > 0 {
		resources = &resourceWatchdogPlan{CPUs: s.CPUs, MemoryBytes: s.MemoryBytes}
	}
	if s.CPUs > 0 {
		caveats = append(caveats, "Seatbelt has no kernel CPU quota; isobox applies a best-effort process-group duty-cycle watchdog outside strict capability accounting")
	}
	if s.MemoryBytes > 0 {
		caveats = append(caveats, "Seatbelt has no kernel memory cap; isobox applies a best-effort process-group memory watchdog that can kill after an over-limit sample")
	}
	var b strings.Builder
	// Start permissive, then carve away. In SBPL the last matching rule wins.
	// Seatbelt can restrict Mach service lookup, but that is narrower than a
	// broad no-host-IPC guarantee.
	b.WriteString("(version 1)\n(allow default)\n(deny mach-lookup)\n")
	uses = uses.Union(NewCapabilitySet(CapMachRestrict))
	// Carve specific Mach services back out of the lookup denial. Allow rules
	// must follow (deny mach-lookup) since SBPL's last match wins.
	machAllow := s.MachAllow
	if s.Net == NetEnable || s.Net == NetOutbound {
		// Networked macOS programs validate TLS certificates through
		// Security.framework, which reaches trustd/securityd over Mach. Re-allow
		// those services so certificate validation works without a manual
		// --mach-allow; the rest of the Mach surface stays denied.
		machAllow = mergeMachServices(s.MachAllow, seatbeltTLSTrustMachServices)
		caveats = append(caveats,
			"Seatbelt re-allows the Apple TLS trust Mach services (com.apple.trustd, com.apple.trustd.agent, com.apple.SecurityServer) while network access is enabled so Security.framework clients can validate certificates")
	}
	for _, name := range machAllow {
		fmt.Fprintf(&b, "(allow mach-lookup (global-name %s))\n", sbplQuote(name))
	}

	switch s.Net {
	case NetDisable:
		b.WriteString("(deny network*)\n")
		uses = uses.Union(NewCapabilitySet(CapNetDisable))
		caveats = append(caveats,
			"Seatbelt net.disable additionally blocks loopback; if your program needs a local AF_INET socket, isobox's portable net.disable cannot be relied on.")
	case NetEnable:
		uses = uses.Union(NewCapabilitySet(CapNetEnable))
	case NetOutbound:
		b.WriteString("(deny network-inbound)\n")
		uses = uses.Union(NewCapabilitySet(CapNetOutbound))
	}

	if len(s.Readable) > 0 {
		b.WriteString(`(deny file-read* (subpath "/"))` + "\n")
		// Runtime loader dependencies needed for confined programs to start.
		sbplSubpaths(&b, "allow", "file-read*", []string{
			"/usr/lib", "/System", "/private/var/db/dyld",
		})
		// /System lexically covers the firmlinked data volume on modern
		// macOS; deny it before the user's reads so the loader widening
		// above cannot leak /System/Volumes/Data. An explicit Readable
		// scope under the data volume still wins (added after this).
		b.WriteString(`(deny file-read* (subpath "/System/Volumes/Data"))` + "\n")
		sbplLiterals(&b, "allow", "file-read*", seatbeltDeviceReadLiterals)
		allow := make([]string, 0, len(s.Readable)+2)
		for _, r := range s.Readable {
			allow = append(allow, canonPath(r))
		}
		if exe, ok := resolveExec(s.Args[0]); ok {
			allow = append(allow, exe)
		}
		if s.Write == WriteEphemeral {
			// The APFS clone replaces cwd at runtime; reads from inside the
			// clone must succeed even under a scoped-read allowlist.
			allow = append(allow, isoboxEphemeralRootPlaceholder)
		}
		sbplSubpaths(&b, "allow", "file-read*", allow)
		caveats = append(caveats,
			"Seatbelt fs.read.scope additionally exposes /usr/lib, /System, and /private/var/db/dyld read-only so dynamic Mach-O binaries can load; this is wider than your --readable allowlist.")
		uses = uses.Union(NewCapabilitySet(CapFSReadScope))
	} else {
		// Broad host read via (allow default): deny raw block/char device
		// nodes so a privileged confined process cannot read host data
		// straight off the disk or kernel memory, bypassing the filesystem.
		b.WriteString(`(deny file-read* (regex #"^/dev/r?disk"))` + "\n")
		b.WriteString(`(deny file-read* (regex #"^/dev/(mem|kmem|kcore)$"))` + "\n")
		caveats = append(caveats,
			"Seatbelt broad host read relies on OS file permissions; raw device nodes (e.g. /dev/rdisk*, /dev/mem) are denied but other device nodes remain readable to privileged callers")
		uses = uses.Union(NewCapabilitySet(CapFSReadHost))
	}
	if len(s.ReadDeny) > 0 {
		deny := make([]string, 0, len(s.ReadDeny))
		for _, r := range s.ReadDeny {
			deny = append(deny, canonPath(r))
		}
		sbplSubpaths(&b, "deny", "file-read*", deny)
		caveats = append(caveats,
			"Seatbelt read-deny matches by path; a hardlink to a denied file from an allowed location reads the same inode and bypasses the denial")
		uses = uses.Union(NewCapabilitySet(CapFSReadDeny))
	}

	temp := []string(nil)
	if s.AllowTemp {
		temp = osTempRoots()
	}
	switch s.Write {
	case WriteNone:
		b.WriteString(`(deny file-write* (subpath "/"))` + "\n")
		sbplLiterals(&b, "allow", "file-write*", seatbeltDeviceWriteLiterals)
		sbplSubpaths(&b, "allow", "file-write*", temp)
		uses = uses.Union(NewCapabilitySet(CapFSWriteDeny))
	case WriteScope:
		b.WriteString(`(deny file-write* (subpath "/"))` + "\n")
		allow := make([]string, 0, len(s.Writable)+len(temp))
		for _, w := range s.Writable {
			allow = append(allow, canonPath(w))
		}
		allow = append(allow, temp...)
		sbplLiterals(&b, "allow", "file-write*", seatbeltDeviceWriteLiterals)
		sbplSubpaths(&b, "allow", "file-write*", allow)
		uses = uses.Union(NewCapabilitySet(CapFSWriteScope))
		caveats = append(caveats,
			"Seatbelt write-scope is path based; a hardlink inside a writable path can modify the same file object through an out-of-scope alias")
	case WriteEphemeral:
		b.WriteString(`(deny file-write* (subpath "/"))` + "\n")
		sbplLiterals(&b, "allow", "file-write*", seatbeltDeviceWriteLiterals)
		sbplSubpaths(&b, "allow", "file-write*", []string{isoboxEphemeralRootPlaceholder})
		uses = uses.Union(NewCapabilitySet(CapFSWriteEphemeral))
		caveats = append(caveats,
			"macOS ephemeral writes are workspace-scoped to Spec.Dir/cwd via an APFS clone, not a whole-host overlay")
	case WriteOverlay:
		b.WriteString(`(deny file-write* (subpath "/"))` + "\n")
		allow := make([]string, 0, len(s.Writable)+len(temp))
		for _, w := range s.Writable {
			allow = append(allow, canonPath(w))
		}
		allow = append(allow, temp...)
		sbplLiterals(&b, "allow", "file-write*", seatbeltDeviceWriteLiterals)
		sbplSubpaths(&b, "allow", "file-write*", allow)
		uses = uses.Union(NewCapabilitySet(CapFSWriteScope))
		caveats = append(caveats,
			"Seatbelt cannot redirect writes outside writable paths to an ephemeral/shadow filesystem; those writes are denied")
		caveats = append(caveats,
			"Seatbelt write-scope is path based; a hardlink inside a writable path can modify the same file object through an out-of-scope alias")
	}

	if s.NoExec {
		exe, ok := resolveExec(s.Args[0])
		if !ok {
			return nil, fmt.Errorf("isobox: NoExec set but cannot resolve executable %q", s.Args[0])
		}
		b.WriteString("(deny process-exec*)\n")
		fmt.Fprintf(&b, "(allow process-exec* (literal %s))\n", sbplQuote(exe))
		caveats = append(caveats, "Seatbelt no-exec is best-effort: it blocks exec of paths other than the initially allowed executable; if that executable is an interpreter (e.g. /bin/sh) it can re-exec itself to load new code")
	}

	profile := b.String()

	// Use the resolved absolute executable so it matches any policy literal.
	cmd := s.Args[0]
	if exe, ok := resolveExec(s.Args[0]); ok {
		cmd = exe
	}
	argv := append([]string{"sandbox-exec", "-p", profile, cmd}, s.Args[1:]...)

	plan := &Plan{
		Backend:   BackendSeatbelt,
		Argv:      argv,
		Profile:   profile,
		Uses:      uses,
		Caveats:   caveats,
		resources: resources,
	}
	if s.Write == WriteEphemeral {
		plan.fs = &fsVirtualizationPlan{
			Kind:      fsVirtualizationMacOSAPFSClone,
			AllowTemp: s.AllowTemp,
		}
	}
	return plan, nil
}
