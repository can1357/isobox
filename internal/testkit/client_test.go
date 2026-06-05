package testkit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClientReportAddCheckAndEvidence(t *testing.T) {
	var report ClientReport
	report.AddCheck("ok", true, nil)
	err := os.ErrNotExist
	report.AddCheck("missing", false, err)
	report.AddEvidence("goos", "test-os")

	if !report.Checks["ok"].Success {
		t.Fatalf("ok check was not recorded as successful")
	}
	if report.Checks["ok"].Error != "" {
		t.Fatalf("ok check recorded unexpected error: %q", report.Checks["ok"].Error)
	}
	if report.Checks["missing"].Success {
		t.Fatalf("missing check was recorded as successful")
	}
	if report.Checks["missing"].Error == "" {
		t.Fatalf("missing check did not record an error")
	}
	if report.Evidence["goos"] != "test-os" {
		t.Fatalf("evidence not recorded: %q", report.Evidence["goos"])
	}
}

func TestRunClientProbeFSReadAllowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "readable.txt")
	if err := os.WriteFile(path, []byte("readable"), 0o666); err != nil {
		t.Fatal(err)
	}

	report, err := RunClientProbe(ClientConfig{
		Probe:   ProbeFSRead,
		Allowed: []string{path},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Probe != ProbeFSRead {
		t.Fatalf("probe = %q, want %q", report.Probe, ProbeFSRead)
	}
	check, ok := report.Checks["allowed"]
	if !ok {
		t.Fatalf("allowed check missing: %#v", report.Checks)
	}
	if !check.Success {
		t.Fatalf("allowed read failed: %s", check.Error)
	}
	if report.Evidence["allowed.path"] != path {
		t.Fatalf("allowed path evidence = %q, want %q", report.Evidence["allowed.path"], path)
	}
}

func TestRunClientProbeFSWriteAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writable.txt")
	report, err := RunClientProbe(ClientConfig{
		Probe:   ProbeFSWrite,
		Allowed: []string{path},
		Content: "written",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Checks["allowed"].Success {
		t.Fatalf("allowed write failed: %s", report.Checks["allowed"].Error)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "written" {
		t.Fatalf("content = %q, want %q", string(data), "written")
	}
}
