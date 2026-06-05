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

const isoboxEphemeralRootPlaceholder = "<isobox-ephemeral-root>"

// compileSeatbelt turns a Spec into a Seatbelt (sandbox-exec) plan. It is pure:
// it builds the SBPL profile and argv but runs nothing.
func compileSeatbelt(s Spec) (*Plan, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	uses := NewCapabilitySet()
	var caveats []string
	if s.CPUs > 0 {
		caveats = append(caveats, "Seatbelt has no CPU-limit mechanism; CPUs is ignored")
	}
	if s.MemoryBytes > 0 {
		caveats = append(caveats, "Seatbelt has no memory-limit mechanism; MemoryBytes is ignored")
	}
	var b strings.Builder
	// Start permissive, then carve away. In SBPL the last matching rule wins.
	// Seatbelt can restrict Mach service lookup, but that is narrower than a
	// broad no-host-IPC guarantee.
	b.WriteString("(version 1)\n(allow default)\n(deny mach-lookup)\n")
	uses = uses.Union(NewCapabilitySet(CapMachRestrict))
	// Carve specific Mach services back out of the lookup denial. The
	// allow rules must follow (deny mach-lookup) since SBPL's last match wins.
	if len(s.MachAllow) > 0 {
		for _, name := range s.MachAllow {
			fmt.Fprintf(&b, "(allow mach-lookup (global-name %s))\n", sbplQuote(name))
		}
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
		Backend: BackendSeatbelt,
		Argv:    argv,
		Profile: profile,
		Uses:    uses,
		Caveats: caveats,
	}
	if s.Write == WriteEphemeral {
		plan.fs = &fsVirtualizationPlan{
			Kind:      fsVirtualizationMacOSAPFSClone,
			AllowTemp: s.AllowTemp,
		}
	}
	return plan, nil
}
