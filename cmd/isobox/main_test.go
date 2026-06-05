package main

import (
	"testing"

	"github.com/can1357/isobox"
)

func TestApplyAgentProfileDefaults(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	spec := isobox.Spec{Args: []string{"echo"}, Dir: "/work"}
	if err := applyProfile("agent", &spec, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if spec.Net != isobox.NetOutbound {
		t.Fatalf("Net=%s, want outbound", spec.Net)
	}
	if spec.Write != isobox.WriteOverlay {
		t.Fatalf("Write=%s, want overlay", spec.Write)
	}
	if !spec.AllowTemp {
		t.Fatal("agent profile should enable temp writes")
	}
	if !hasPath(spec.Writable, "/work") {
		t.Fatalf("workspace writable missing: %v", spec.Writable)
	}
	if len(spec.ReadDeny) == 0 {
		t.Fatal("agent profile should install sensitive read deny defaults")
	}
}

func TestApplyAgentProfileHonorsExplicitOverrides(t *testing.T) {
	spec := isobox.Spec{
		Args:     []string{"echo"},
		Net:      isobox.NetDisable,
		Write:    isobox.WriteNone,
		Readable: []string{"/project"},
	}
	seen := map[string]bool{"net": true, "write": true, "readable": true, "allow-temp": true}
	if err := applyProfile("agent", &spec, seen); err != nil {
		t.Fatal(err)
	}
	if spec.Net != isobox.NetDisable || spec.Write != isobox.WriteNone || spec.AllowTemp {
		t.Fatalf("explicit overrides not preserved: %+v", spec)
	}
	if len(spec.Writable) != 0 {
		t.Fatalf("explicit write=none should not gain writable paths: %v", spec.Writable)
	}
	if len(spec.ReadDeny) != 0 {
		t.Fatalf("explicit readable should suppress default read deny list: %v", spec.ReadDeny)
	}
}

func TestStrictWithoutExplicitProfileKeepsTightDefaults(t *testing.T) {
	spec := isobox.Spec{Args: []string{"echo"}, Strict: true}
	if err := applyProfile("agent", &spec, map[string]bool{"strict": true}); err != nil {
		t.Fatal(err)
	}
	if spec.Net != isobox.NetDisable || spec.Write != isobox.WriteNone || len(spec.Writable) != 0 || len(spec.ReadDeny) != 0 {
		t.Fatalf("strict should keep tight defaults unless profile is explicit: %+v", spec)
	}
}

func hasPath(paths []string, want string) bool {
	for _, path := range paths {
		if path == want {
			return true
		}
	}
	return false
}

func TestParseMachAllowFlag(t *testing.T) {
	fs := newFlagSet()
	var machAllow stringList
	fs.Var(&machAllow, "mach-allow", "")
	if err := fs.Parse([]string{"--mach-allow", "a", "--mach-allow", "b", "--", "echo"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := []string(machAllow)
	want := []string{"a", "b"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("MachAllow=%v, want %v", got, want)
	}
	if args := fs.Args(); len(args) != 1 || args[0] != "echo" {
		t.Fatalf("positional args=%v, want [echo]", args)
	}
}
