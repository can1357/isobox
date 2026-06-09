package isobox

import "testing"

func TestSpecCapabilitiesMapping(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		want []Capability
		not  []Capability
	}{
		{
			name: "portable default",
			spec: Spec{Args: []string{"echo"}},
			want: []Capability{CapNetDisable, CapFSWriteDeny, CapFSReadHost},
		},
		{
			name: "outbound + scoped writes + scoped reads",
			spec: Spec{Args: []string{"x"}, Net: NetOutbound, Write: WriteScope, Writable: []string{"/w"}, Readable: []string{"/r"}},
			want: []Capability{CapNetOutbound, CapFSWriteScope, CapFSReadScope},
			not:  []Capability{CapFSReadHost, CapNetDisable},
		},
		{
			name: "overlay + broad reads with denylist",
			spec: Spec{Args: []string{"x"}, Net: NetOutbound, Write: WriteOverlay, Writable: []string{"/work"}, AllowTemp: true, ReadDeny: []string{"/secret"}},
			want: []Capability{CapNetOutbound, CapFSWriteScope, CapFSWriteEphemeral, CapFSReadHost, CapFSReadDeny},
			not:  []Capability{CapFSWriteDeny, CapNetDisable},
		},
		{
			name: "ephemeral + no-exec + enable",
			spec: Spec{Args: []string{"x"}, Net: NetEnable, Write: WriteEphemeral, NoExec: true},
			want: []Capability{CapNetEnable, CapFSWriteEphemeral, CapProcNoExec, CapFSReadHost},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.spec.Capabilities()
			for _, c := range tc.want {
				if !got.Has(c) {
					t.Errorf("missing %s; have %v", c, got.List())
				}
			}
			for _, c := range tc.not {
				if got.Has(c) {
					t.Errorf("unexpected %s; have %v", c, got.List())
				}
			}
		})
	}
}

func TestSpecValidate(t *testing.T) {
	cases := []struct {
		name    string
		spec    Spec
		wantErr bool
	}{
		{"empty args", Spec{}, true},
		{"empty exe", Spec{Args: []string{""}}, true},
		{"ok minimal", Spec{Args: []string{"echo"}}, false},
		{"scope without targets", Spec{Args: []string{"x"}, Write: WriteScope}, true},
		{"scope with temp ok", Spec{Args: []string{"x"}, Write: WriteScope, AllowTemp: true}, false},
		{"blank readable", Spec{Args: []string{"x"}, Readable: []string{" "}}, true},
		{"blank writable", Spec{Args: []string{"x"}, Write: WriteScope, Writable: []string{"\t"}}, true},
		{"temp requires scoped or overlay writes", Spec{Args: []string{"x"}, AllowTemp: true}, true},
		{"writable requires scoped or overlay writes", Spec{Args: []string{"x"}, Writable: []string{"/w"}}, true},
		{"readable dir under readable ok", Spec{Args: []string{"x"}, Dir: "/r/project", Readable: []string{"/r"}}, false},
		{"readable dir under writable ok", Spec{Args: []string{"x"}, Dir: "/w/project", Readable: []string{"/r"}, Write: WriteScope, Writable: []string{"/w"}}, false},
		{"overlay with temp ok", Spec{Args: []string{"x"}, Write: WriteOverlay, AllowTemp: true}, false},
		{"overlay with writable ok", Spec{Args: []string{"x"}, Write: WriteOverlay, Writable: []string{"/w"}}, false},
		{"blank read deny", Spec{Args: []string{"x"}, ReadDeny: []string{" "}}, true},
		{"readable dir outside scopes", Spec{Args: []string{"x"}, Dir: "/work", Readable: []string{"/r"}}, true},
		{"strict minimal follows intersection", Spec{Args: []string{"x"}, Net: NetEnable, Write: WriteNone, Strict: true}, strictRejects(Spec{Args: []string{"x"}, Net: NetEnable, Write: WriteNone})},
		{"strict outbound follows intersection", Spec{Args: []string{"x"}, Net: NetOutbound, Strict: true}, strictRejects(Spec{Args: []string{"x"}, Net: NetOutbound})},
		{"strict scoped-write follows intersection", Spec{Args: []string{"x"}, Write: WriteScope, Writable: []string{"/w"}, Strict: true}, strictRejects(Spec{Args: []string{"x"}, Write: WriteScope, Writable: []string{"/w"}})},
		{"strict scoped-read follows intersection", Spec{Args: []string{"x"}, Readable: []string{"/r"}, Strict: true}, strictRejects(Spec{Args: []string{"x"}, Readable: []string{"/r"}})},
		{"strict no-exec follows intersection", Spec{Args: []string{"x"}, NoExec: true, Strict: true}, strictRejects(Spec{Args: []string{"x"}, NoExec: true})},
		{"strict read-deny follows intersection", Spec{Args: []string{"x"}, ReadDeny: []string{"/secret"}, Strict: true}, strictRejects(Spec{Args: []string{"x"}, ReadDeny: []string{"/secret"}})},
		{"strict overlay follows intersection", Spec{Args: []string{"x"}, Write: WriteOverlay, Writable: []string{"/w"}, Strict: true}, strictRejects(Spec{Args: []string{"x"}, Write: WriteOverlay, Writable: []string{"/w"}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestPlanFilesystemVirtualization(t *testing.T) {
	defaultPlan, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := defaultPlan.FilesystemVirtualization(); got != "" {
		t.Fatalf("default plan FilesystemVirtualization()=%q, want empty", got)
	}

	seatbeltEphemeral, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Write: WriteEphemeral})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := seatbeltEphemeral.FilesystemVirtualization(), string(fsVirtualizationMacOSAPFSClone); got != want {
		t.Fatalf("Seatbelt WriteEphemeral FilesystemVirtualization()=%q, want %q", got, want)
	}

	gvisorScoped, err := compileGvisor(Spec{
		Args:     []string{"x"},
		Write:    WriteScope,
		Writable: []string{"/w"},
		Readable: []string{"/r"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := gvisorScoped.FilesystemVirtualization(), string(fsVirtualizationLinuxNamespaceView); got != want {
		t.Fatalf("gVisor scoped read/write FilesystemVirtualization()=%q, want %q", got, want)
	}
}

func strictRejects(s Spec) bool {
	return s.Capabilities().Sub(Intersection()).Len() > 0
}

func TestSpecResourceCapabilities(t *testing.T) {
	none := Spec{Args: []string{"x"}}.Capabilities()
	if none.Has(CapResCPU) || none.Has(CapResMemory) || none.Has(CapResPIDs) {
		t.Fatalf("no limits must not request resource capabilities: %v", none.List())
	}
	both := Spec{Args: []string{"x"}, CPUs: 1.5, MemoryBytes: 1 << 20, PIDs: 64}.Capabilities()
	if !both.Has(CapResCPU) || !both.Has(CapResMemory) || !both.Has(CapResPIDs) {
		t.Fatalf("limits must request res.cpu/res.memory/res.pids: %v", both.List())
	}
	cpuOnly := Spec{Args: []string{"x"}, CPUs: 2}.Capabilities()
	if !cpuOnly.Has(CapResCPU) || cpuOnly.Has(CapResMemory) || cpuOnly.Has(CapResPIDs) {
		t.Fatalf("CPU-only must request only res.cpu: %v", cpuOnly.List())
	}
	memOnly := Spec{Args: []string{"x"}, MemoryBytes: 1 << 20}.Capabilities()
	if memOnly.Has(CapResCPU) || !memOnly.Has(CapResMemory) || memOnly.Has(CapResPIDs) {
		t.Fatalf("memory-only must request only res.memory: %v", memOnly.List())
	}
	pidsOnly := Spec{Args: []string{"x"}, PIDs: 64}.Capabilities()
	if pidsOnly.Has(CapResCPU) || pidsOnly.Has(CapResMemory) || !pidsOnly.Has(CapResPIDs) {
		t.Fatalf("PIDs-only must request only res.pids: %v", pidsOnly.List())
	}
}

func TestSpecValidateResourceLimits(t *testing.T) {
	if err := (Spec{Args: []string{"x"}, CPUs: -1}).validate(); err == nil {
		t.Error("negative CPUs must be rejected")
	}
	if err := (Spec{Args: []string{"x"}, MemoryBytes: -1}).validate(); err == nil {
		t.Error("negative MemoryBytes must be rejected")
	}
	if err := (Spec{Args: []string{"x"}, PIDs: -1}).validate(); err == nil {
		t.Error("negative PIDs must be rejected")
	}
	if err := (Spec{Args: []string{"x"}, PIDs: 1 << 32}).validate(); err == nil {
		t.Error("PIDs larger than Windows job-object active process limit must be rejected")
	}
	if err := (Spec{Args: []string{"x"}, CPUs: 1.5, MemoryBytes: 1 << 20, PIDs: 64}).validate(); err != nil {
		t.Errorf("valid resource limits rejected: %v", err)
	}
	// Resource limits are portable across OS-compatible backend unions: macOS can
	// use Docker/runsc, Linux can use gVisor/Docker, and Windows uses jobs.
	if err := (Spec{Args: []string{"x"}, Readable: []string{"/work"}, CPUs: 1, Strict: true}).validate(); err != nil {
		t.Errorf("strict should allow a portable CPU limit with scoped reads: %v", err)
	}
	if err := (Spec{Args: []string{"x"}, Readable: []string{"/work"}, MemoryBytes: 1 << 20, Strict: true}).validate(); err != nil {
		t.Errorf("strict should allow a portable memory limit: %v", err)
	}
	if err := (Spec{Args: []string{"x"}, Readable: []string{"/work"}, PIDs: 64, Strict: true}).validate(); err != nil {
		t.Errorf("strict should allow a portable process-count limit: %v", err)
	}
}
