package isobox

import "testing"

func TestSelectBackendForSpecPrefersNativeWhenItSatisfies(t *testing.T) {
	b, err := selectBackendForSpec("darwin", Spec{
		Args:     []string{"echo"},
		Net:      NetOutbound,
		Write:    WriteOverlay,
		ReadDeny: []string{"/secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if b != BackendSeatbelt {
		t.Fatalf("backend=%s, want %s", b, BackendSeatbelt)
	}
}

func TestSelectBackendForSpecCanUseDockerRunscOnDarwin(t *testing.T) {
	b, err := selectBackendForSpec("darwin", Spec{
		Args:        []string{"echo"},
		Readable:    []string{"/work"},
		MemoryBytes: 128 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if b != BackendDockerRunscEphemeral {
		t.Fatalf("backend=%s, want %s", b, BackendDockerRunscEphemeral)
	}
}

func TestSelectBackendForSpecFallsBackToNativeWhenNoCandidateCoversAll(t *testing.T) {
	b, err := selectBackendForSpec("darwin", Spec{
		Args:        []string{"echo"},
		Readable:    []string{"/work"},
		NoExec:      true,
		MemoryBytes: 128 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if b != BackendSeatbelt {
		t.Fatalf("backend=%s, want native fallback %s", b, BackendSeatbelt)
	}
}

func TestSelectBackendForSpecLinuxPrefersGvisor(t *testing.T) {
	b, err := selectBackendForSpec("linux", Spec{Args: []string{"echo"}, NoExec: true})
	if err != nil {
		t.Fatal(err)
	}
	if b != BackendGvisor {
		t.Fatalf("backend=%s, want %s", b, BackendGvisor)
	}
}

func TestSelectBackendForSpecUnsupportedOS(t *testing.T) {
	if _, err := selectBackendForSpec("plan9", Spec{Args: []string{"echo"}}); err == nil {
		t.Fatal("expected unsupported OS error")
	}
}
