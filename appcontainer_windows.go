//go:build windows

package isobox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	procThreadAttributeSecurityCapabilities     = 0x00020009
	procThreadAttributeChildProcessPolicy       = 0x0002000e
	procThreadAttributeAllAppPackagesPolicy     = 0x0002000f
	processCreationChildProcessRestricted       = 0x00000001
	processCreationAllApplicationPackagesOptOut = 0x00000001

	hresultAppContainerAlreadyExists = 0x800700b7

	fileDeleteChild windows.ACCESS_MASK = 0x00000040

	// CPU rate control flags for JOBOBJECT_CPU_RATE_CONTROL_INFORMATION.
	jobObjectCPURateControlEnable  = 0x00000001
	jobObjectCPURateControlHardCap = 0x00000004
)

type securityCapabilities struct {
	AppContainerSid *windows.SID
	Capabilities    *windows.SIDAndAttributes
	CapabilityCount uint32
	Reserved        uint32
}

// jobObjectCPURateControlInformation mirrors the Win32
// JOBOBJECT_CPU_RATE_CONTROL_INFORMATION struct (the leading union member is
// CpuRate, a DWORD). x/sys/windows defines the info class constant but not the
// struct.
type jobObjectCPURateControlInformation struct {
	ControlFlags uint32
	Rate         uint32
}

var (
	modUserenv                          = windows.NewLazySystemDLL("userenv.dll")
	procDeriveAppContainerSidFromName   = modUserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
	procCreateAppContainerProfile       = modUserenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile       = modUserenv.NewProc("DeleteAppContainerProfile")
	errAppContainerProfileAlreadyExists = errors.New("appcontainer profile already exists")
)

func runAppContainer(ctx context.Context, plan *Plan, s Spec, streams Stdio) (exitCode int, retErr error) {
	profile := plan.ac
	if profile == nil {
		return -1, fmt.Errorf("isobox: appcontainer plan missing structured profile")
	}
	fsRuntime, err := prepareFSVirtualization(plan, s)
	if err != nil {
		return -1, err
	}
	appendPlanFSCaveats(plan, fsRuntime)
	cleanup := func() error { return nil }
	if fsRuntime != nil && fsRuntime.Cleanup != nil {
		cleanup = fsRuntime.Cleanup
	}
	defer func() {
		if cleanupErr := cleanup(); cleanupErr != nil {
			wrapped := fmt.Errorf("isobox: cleaning filesystem virtualization: %w", cleanupErr)
			if retErr != nil {
				retErr = errors.Join(retErr, wrapped)
				return
			}
			exitCode = -1
			retErr = wrapped
		}
	}()

	var appSID *windows.SID
	if profile.DeriveOnlyLowbox {
		appSID, err = deriveAppContainerSID(profile.ProfileName)
	} else {
		appSID, _, err = ensureAppContainerProfile(profile.ProfileName)
	}
	if err != nil {
		return -1, err
	}
	defer windows.FreeSid(appSID)
	if !profile.DeriveOnlyLowbox {
		// R6: per-run unique profile names mean the profile we just ensured is the
		// one we own; always delete it on exit (success, error, signal) so a crashed
		// or killed run cannot leak stale ACEs into a future run. Best-effort:
		// deleteAppContainerProfile is idempotent and swallows errors.
		defer deleteAppContainerProfile(profile.ProfileName)
	}

	var applied []aclGrant
	for _, path := range profile.ReadDeny {
		if _, err := os.Lstat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return -1, fmt.Errorf("isobox: checking AppContainer read-deny path %s: %w", path, err)
		}
		grant := aclGrant{path: path, access: windows.GENERIC_READ | windows.GENERIC_EXECUTE, deny: true}
		if err := applyACLGrantTree(appSID, grant, &applied); err != nil {
			return -1, err
		}
	}
	defer cleanupACLGrants(appSID, &applied)
	traversalGranted := make(map[string]struct{})
	for _, path := range profile.ReadGrants {
		if err := applyACLTraversalGrants(appSID, path, traversalGranted, &applied); err != nil {
			return -1, err
		}
		grant := aclGrant{path: path, access: windows.GENERIC_READ | windows.GENERIC_EXECUTE}
		if err := applyACLGrantTree(appSID, grant, &applied); err != nil {
			return -1, err
		}
	}
	for _, path := range profile.WriteGrants {
		if err := applyACLTraversalGrants(appSID, path, traversalGranted, &applied); err != nil {
			return -1, err
		}
		grant := aclGrant{path: path, access: windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE | windows.DELETE | fileDeleteChild}
		if err := applyACLGrantTree(appSID, grant, &applied); err != nil {
			return -1, err
		}
	}

	capAttrs, err := buildCapabilityAttrs(profile.CapabilitySIDs)
	if err != nil {
		return -1, err
	}
	secCaps := securityCapabilities{AppContainerSid: appSID, CapabilityCount: uint32(len(capAttrs))}
	if len(capAttrs) > 0 {
		secCaps.Capabilities = &capAttrs[0]
	}

	stdio, err := prepareAppContainerStdio(streams)
	if err != nil {
		return -1, err
	}
	defer stdio.closeAll()

	attrCount := uint32(2) // security capabilities + handle list
	if profile.LPAC {
		attrCount++
	}
	if profile.ChildRestricted {
		attrCount++
	}
	attrs, err := windows.NewProcThreadAttributeList(attrCount)
	if err != nil {
		return -1, fmt.Errorf("isobox: creating AppContainer attribute list: %w", err)
	}
	defer attrs.Delete()
	if err := attrs.Update(procThreadAttributeSecurityCapabilities, unsafe.Pointer(&secCaps), unsafe.Sizeof(secCaps)); err != nil {
		return -1, fmt.Errorf("isobox: setting AppContainer security capabilities: %w", err)
	}
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&stdio.childHandles[0]), uintptr(len(stdio.childHandles))*unsafe.Sizeof(stdio.childHandles[0])); err != nil {
		return -1, fmt.Errorf("isobox: setting AppContainer handle list: %w", err)
	}
	allAppPackagesPolicy := uint32(processCreationAllApplicationPackagesOptOut)
	if profile.LPAC {
		if err := attrs.Update(procThreadAttributeAllAppPackagesPolicy, unsafe.Pointer(&allAppPackagesPolicy), unsafe.Sizeof(allAppPackagesPolicy)); err != nil {
			return -1, fmt.Errorf("isobox: setting AppContainer all-application-packages policy: %w", err)
		}
	}
	childPolicy := uint32(processCreationChildProcessRestricted)
	if profile.ChildRestricted {
		if err := attrs.Update(procThreadAttributeChildProcessPolicy, unsafe.Pointer(&childPolicy), unsafe.Sizeof(childPolicy)); err != nil {
			return -1, fmt.Errorf("isobox: setting AppContainer child process policy: %w", err)
		}
	}

	exe16, err := windows.UTF16PtrFromString(profile.Exe)
	if err != nil {
		return -1, fmt.Errorf("isobox: encoding executable path: %w", err)
	}
	cmdline16, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(profile.Argv))
	if err != nil {
		return -1, fmt.Errorf("isobox: encoding command line: %w", err)
	}
	var dir16 *uint16
	if profile.WorkDir != "" {
		dir16, err = windows.UTF16PtrFromString(profile.WorkDir)
		if err != nil {
			return -1, fmt.Errorf("isobox: encoding working directory: %w", err)
		}
	}
	envBlock, err := windowsEnvironmentBlock(finalEnv(s, nil))
	if err != nil {
		return -1, err
	}
	var env16 *uint16
	if len(envBlock) > 0 {
		env16 = &envBlock[0]
	}

	si := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:        uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags:     windows.STARTF_USESTDHANDLES,
			StdInput:  stdio.stdin,
			StdOutput: stdio.stdout,
			StdErr:    stdio.stderr,
		},
		ProcThreadAttributeList: attrs.List(),
	}
	var pi windows.ProcessInformation
	limited := profile.CPUs > 0 || profile.MemoryBytes > 0 || profile.PIDs > 0
	creationFlags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT)
	if limited {
		// Start suspended so the resource-limit job is attached before the
		// process runs any code.
		creationFlags |= windows.CREATE_SUSPENDED
	}
	if err := windows.CreateProcess(exe16, cmdline16, nil, nil, true, creationFlags, env16, dir16, &si.StartupInfo, &pi); err != nil {
		return -1, fmt.Errorf("isobox: launching appcontainer backend: %w", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	stdio.closeChildHandles()
	stdio.startPumps()
	if limited {
		job, err := applyResourceLimits(pi.Process, profile.CPUs, profile.MemoryBytes, profile.PIDs)
		if err != nil {
			windows.TerminateProcess(pi.Process, 1)
			return -1, err
		}
		defer windows.CloseHandle(job)
		if _, err := windows.ResumeThread(pi.Thread); err != nil {
			windows.TerminateProcess(pi.Process, 1)
			return -1, fmt.Errorf("isobox: resuming appcontainer process: %w", err)
		}
	}

	waitErr := waitForProcess(ctx, pi.Process)
	var exit uint32
	if err := windows.GetExitCodeProcess(pi.Process, &exit); err != nil {
		return -1, fmt.Errorf("isobox: reading appcontainer exit code: %w", err)
	}
	if pumpErr := stdio.waitPumps(); pumpErr != nil {
		return -1, pumpErr
	}
	if waitErr != nil {
		return -1, waitErr
	}

	runtime.KeepAlive(capAttrs)
	runtime.KeepAlive(secCaps)
	runtime.KeepAlive(stdio.childHandles)
	runtime.KeepAlive(envBlock)
	return int(exit), nil
}

// applyResourceLimits creates a job object that caps the process's memory,
// CPU, and/or active process count, then assigns the process to it. The returned
// job handle must be kept open for the lifetime of the process; closing it
// (KILL_ON_JOB_CLOSE) terminates any survivors.
func applyResourceLimits(process windows.Handle, cpus float64, memoryBytes int64, pids int64) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("isobox: creating resource-limit job object: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if memoryBytes > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_MEMORY
		info.JobMemoryLimit = uintptr(memoryBytes)
	}
	if pids > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		info.BasicLimitInformation.ActiveProcessLimit = uint32(pids)
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("isobox: setting job object limits: %w", err)
	}
	if cpus > 0 {
		cpuInfo := jobObjectCPURateControlInformation{
			ControlFlags: jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
			Rate:         cpuRateHundredths(cpus),
		}
		if _, err := windows.SetInformationJobObject(job, windows.JobObjectCpuRateControlInformation, uintptr(unsafe.Pointer(&cpuInfo)), uint32(unsafe.Sizeof(cpuInfo))); err != nil {
			windows.CloseHandle(job)
			return 0, fmt.Errorf("isobox: setting job cpu rate limit: %w", err)
		}
	}
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("isobox: assigning process to resource-limit job: %w", err)
	}
	return job, nil
}

func waitForProcess(ctx context.Context, process windows.Handle) error {
	done := make(chan error, 1)
	go func() {
		_, err := windows.WaitForSingleObject(process, windows.INFINITE)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("isobox: waiting for appcontainer process: %w", err)
		}
		return nil
	case <-ctx.Done():
		_ = windows.TerminateProcess(process, 1)
		if err := <-done; err != nil {
			return fmt.Errorf("isobox: waiting for terminated appcontainer process: %w", err)
		}
		return nil
	}
}

func ensureAppContainerProfile(name string) (*windows.SID, bool, error) {
	sid, err := createAppContainerProfile(name)
	if err == nil {
		return sid, true, nil
	}
	if !errors.Is(err, errAppContainerProfileAlreadyExists) {
		return nil, false, err
	}
	sid, err = deriveAppContainerSID(name)
	if err != nil {
		return nil, false, err
	}
	return sid, false, nil
}

func createAppContainerProfile(name string) (*windows.SID, error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	desc := "isobox AppContainer sandbox profile"
	desc16, err := windows.UTF16PtrFromString(desc)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	r1, _, _ := procCreateAppContainerProfile.Call(
		uintptr(unsafe.Pointer(name16)),
		uintptr(unsafe.Pointer(name16)),
		uintptr(unsafe.Pointer(desc16)),
		0,
		0,
		uintptr(unsafe.Pointer(&sid)),
	)
	if r1 == hresultAppContainerAlreadyExists {
		return nil, errAppContainerProfileAlreadyExists
	}
	if err := hresultError("CreateAppContainerProfile", r1); err != nil {
		return nil, err
	}
	return sid, nil
}

func deriveAppContainerSID(name string) (*windows.SID, error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	r1, _, _ := procDeriveAppContainerSidFromName.Call(
		uintptr(unsafe.Pointer(name16)),
		uintptr(unsafe.Pointer(&sid)),
	)
	if err := hresultError("DeriveAppContainerSidFromAppContainerName", r1); err != nil {
		return nil, err
	}
	return sid, nil
}

func deleteAppContainerProfile(name string) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(name16)))
}

func hresultError(proc string, hr uintptr) error {
	if hr == 0 {
		return nil
	}
	return fmt.Errorf("isobox: %s failed with HRESULT 0x%08x", proc, uint32(hr))
}

func buildCapabilityAttrs(sids []acCapabilitySID) ([]windows.SIDAndAttributes, error) {
	attrs := make([]windows.SIDAndAttributes, 0, len(sids))
	for _, sidType := range sids {
		sid, err := windows.CreateWellKnownSid(windows.WELL_KNOWN_SID_TYPE(sidType))
		if err != nil {
			return nil, fmt.Errorf("isobox: creating AppContainer capability SID %s: %w", sidType, err)
		}
		attrs = append(attrs, windows.SIDAndAttributes{Sid: sid, Attributes: windows.SE_GROUP_ENABLED})
	}
	return attrs, nil
}

type aclGrant struct {
	path           string
	access         windows.ACCESS_MASK
	inheritance    uint32
	hasInheritance bool
	deny           bool
}

func applyACLGrant(sid *windows.SID, grant aclGrant) error {
	mode := windows.ACCESS_MODE(windows.GRANT_ACCESS)
	if grant.deny {
		mode = windows.DENY_ACCESS
	}
	if grant.hasInheritance {
		return updatePathACLWithInheritance(sid, grant.path, grant.access, mode, grant.inheritance)
	}
	return updatePathACL(sid, grant.path, grant.access, mode)
}

func revokeACLGrant(sid *windows.SID, grant aclGrant) error {
	if grant.hasInheritance {
		return updatePathACLWithInheritance(sid, grant.path, 0, windows.REVOKE_ACCESS, grant.inheritance)
	}
	return updatePathACL(sid, grant.path, 0, windows.REVOKE_ACCESS)
}

func applyACLGrantTree(sid *windows.SID, grant aclGrant, applied *[]aclGrant) error {
	// Windows path-based ACL APIs follow reparse points (symlinks/junctions) to
	// their target, so a pre-existing reparse point — at the grant root or
	// anywhere inside the tree — would grant the AppContainer SID access on an
	// out-of-scope target. Lstat the root (and DirEntry-test every child) so we
	// never apply grants to, or descend through, a reparse point.
	rootInfo, err := os.Lstat(grant.path)
	if err != nil {
		return fmt.Errorf("isobox: checking ACL grant path %s: %w", grant.path, err)
	}
	if rootInfo.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil
	}

	if err := applyACLGrant(sid, grant); err != nil {
		return err
	}
	*applied = append(*applied, grant)

	if !rootInfo.IsDir() {
		return nil
	}

	return filepath.WalkDir(grant.path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("isobox: walking ACL grant path %s: %w", path, err)
		}
		if path == grant.path {
			return nil
		}
		// Skip reparse points without granting or descending: applying a
		// path-based ACE here would follow the link to an out-of-scope target.
		if d.Type()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		childGrant := grant
		childGrant.path = path
		if err := applyACLGrant(sid, childGrant); err != nil {
			return err
		}
		*applied = append(*applied, childGrant)
		return nil
	})
}

func cleanupACLGrants(sid *windows.SID, grants *[]aclGrant) {
	for i := len(*grants) - 1; i >= 0; i-- {
		_ = revokeACLGrant(sid, (*grants)[i])
	}
}

func applyACLTraversalGrants(sid *windows.SID, target string, seen map[string]struct{}, applied *[]aclGrant) error {
	for _, parent := range pathTraversalAncestors(target) {
		if _, ok := seen[parent]; ok {
			continue
		}
		grant := aclGrant{
			path:           parent,
			access:         windows.GENERIC_READ | windows.GENERIC_EXECUTE,
			inheritance:    windows.NO_INHERITANCE,
			hasInheritance: true,
		}
		if err := applyACLGrant(sid, grant); err != nil {
			return err
		}
		seen[parent] = struct{}{}
		*applied = append(*applied, grant)
	}
	return nil
}

func pathTraversalAncestors(target string) []string {
	clean := filepath.Clean(target)
	parents := []string(nil)
	for parent := filepath.Dir(clean); parent != "." && parent != clean; parent = filepath.Dir(clean) {
		parents = append(parents, parent)
		clean = parent
	}
	for i, j := 0, len(parents)-1; i < j; i, j = i+1, j-1 {
		parents[i], parents[j] = parents[j], parents[i]
	}
	return parents
}

func updatePathACL(sid *windows.SID, path string, access windows.ACCESS_MASK, mode windows.ACCESS_MODE) error {
	return updatePathACLWithInheritance(sid, path, access, mode, aclInheritance(path))
}

func updatePathACLWithInheritance(sid *windows.SID, path string, access windows.ACCESS_MASK, mode windows.ACCESS_MODE, inheritance uint32) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("isobox: reading ACL for %s: %w", path, err)
	}
	var oldDACL *windows.ACL
	if sd != nil {
		oldDACL, _, err = sd.DACL()
		if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			return fmt.Errorf("isobox: reading DACL for %s: %w", path, err)
		}
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: access,
		AccessMode:        mode,
		Inheritance:       inheritance,
		Trustee:           appContainerTrustee(sid),
	}
	newDACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, oldDACL)
	if err != nil {
		return fmt.Errorf("isobox: building ACL for %s: %w", path, err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, newDACL, nil); err != nil {
		return fmt.Errorf("isobox: applying ACL for %s: %w", path, err)
	}
	return nil
}

func aclInheritance(path string) uint32 {
	info, err := os.Stat(path)
	if err == nil && info.IsDir() {
		return windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	return windows.NO_INHERITANCE
}

func appContainerTrustee(sid *windows.SID) windows.TRUSTEE {
	return windows.TRUSTEE{
		TrusteeForm:  windows.TRUSTEE_IS_SID,
		TrusteeType:  windows.TRUSTEE_IS_GROUP,
		TrusteeValue: windows.TrusteeValueFromSID(sid),
	}
}

type appContainerStdio struct {
	stdin        windows.Handle
	stdout       windows.Handle
	stderr       windows.Handle
	childHandles []windows.Handle
	parentFiles  []*os.File
	pumps        []func() error
	wg           sync.WaitGroup
	errCh        chan error
	started      bool
}

func prepareAppContainerStdio(streams Stdio) (*appContainerStdio, error) {
	in, out, errw := streams.orDefaults()
	stdio := &appContainerStdio{errCh: make(chan error, 3)}
	var err error
	if stdio.stdin, err = stdio.stdinHandle(in); err != nil {
		stdio.closeAll()
		return nil, err
	}
	if stdio.stdout, err = stdio.outputHandle(out, "stdout"); err != nil {
		stdio.closeAll()
		return nil, err
	}
	if stdio.stderr, err = stdio.outputHandle(errw, "stderr"); err != nil {
		stdio.closeAll()
		return nil, err
	}
	return stdio, nil
}

func (s *appContainerStdio) stdinHandle(in io.Reader) (windows.Handle, error) {
	if f, ok := in.(*os.File); ok {
		return s.duplicateChildHandle(windows.Handle(f.Fd()))
	}
	readHandle, writeHandle, err := inheritablePipe()
	if err != nil {
		return 0, fmt.Errorf("isobox: creating stdin pipe: %w", err)
	}
	if err := windows.SetHandleInformation(writeHandle, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.CloseHandle(readHandle)
		windows.CloseHandle(writeHandle)
		return 0, fmt.Errorf("isobox: securing stdin pipe: %w", err)
	}
	writeFile := os.NewFile(uintptr(writeHandle), "isobox-stdin")
	s.parentFiles = append(s.parentFiles, writeFile)
	s.childHandles = append(s.childHandles, readHandle)
	s.pumps = append(s.pumps, func() error {
		defer writeFile.Close()
		_, err := io.Copy(writeFile, in)
		return err
	})
	return readHandle, nil
}

func (s *appContainerStdio) outputHandle(out io.Writer, name string) (windows.Handle, error) {
	if f, ok := out.(*os.File); ok {
		return s.duplicateChildHandle(windows.Handle(f.Fd()))
	}
	readHandle, writeHandle, err := inheritablePipe()
	if err != nil {
		return 0, fmt.Errorf("isobox: creating %s pipe: %w", name, err)
	}
	if err := windows.SetHandleInformation(readHandle, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.CloseHandle(readHandle)
		windows.CloseHandle(writeHandle)
		return 0, fmt.Errorf("isobox: securing %s pipe: %w", name, err)
	}
	readFile := os.NewFile(uintptr(readHandle), "isobox-"+name)
	s.parentFiles = append(s.parentFiles, readFile)
	s.childHandles = append(s.childHandles, writeHandle)
	s.pumps = append(s.pumps, func() error {
		defer readFile.Close()
		_, err := io.Copy(out, readFile)
		return err
	})
	return writeHandle, nil
}

func (s *appContainerStdio) duplicateChildHandle(src windows.Handle) (windows.Handle, error) {
	var dup windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), src, windows.CurrentProcess(), &dup, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return 0, fmt.Errorf("isobox: duplicating stdio handle: %w", err)
	}
	s.childHandles = append(s.childHandles, dup)
	return dup, nil
}

func inheritablePipe() (readHandle, writeHandle windows.Handle, err error) {
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	err = windows.CreatePipe(&readHandle, &writeHandle, &sa, 0)
	return
}

func (s *appContainerStdio) startPumps() {
	if s.started {
		return
	}
	s.started = true
	for _, pump := range s.pumps {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := pump(); err != nil {
				s.errCh <- err
			}
		}()
	}
}

func (s *appContainerStdio) waitPumps() error {
	s.wg.Wait()
	close(s.errCh)
	for err := range s.errCh {
		if err != nil {
			return fmt.Errorf("isobox: appcontainer stdio copy: %w", err)
		}
	}
	return nil
}

func (s *appContainerStdio) closeChildHandles() {
	for _, h := range s.childHandles {
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
	}
	s.childHandles = nil
}

func (s *appContainerStdio) closeAll() {
	s.closeChildHandles()
	if !s.started {
		for _, f := range s.parentFiles {
			_ = f.Close()
		}
	}
}

func windowsEnvironmentBlock(env []string) ([]uint16, error) {
	if env == nil {
		return nil, nil
	}
	env = append([]string(nil), env...)
	sort.SliceStable(env, func(i, j int) bool {
		return strings.ToUpper(windowsEnvKey(env[i])) < strings.ToUpper(windowsEnvKey(env[j]))
	})
	block := make([]uint16, 0)
	for _, entry := range env {
		if strings.IndexByte(entry, 0) >= 0 {
			return nil, fmt.Errorf("isobox: environment entry contains NUL: %q", entry)
		}
		block = append(block, utf16.Encode([]rune(entry))...)
		block = append(block, 0)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	block = append(block, 0)
	return block, nil
}

func windowsEnvKey(entry string) string {
	if i := strings.IndexByte(entry, '='); i >= 0 {
		return entry[:i]
	}
	return entry
}
