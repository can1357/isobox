package isobox

import (
	"reflect"
	"testing"
)

func TestFinalEnvScrubsInheritedSecrets(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "anthropic")
	t.Setenv("GITHUB_TOKEN", "github")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	t.Setenv("ISOBOX_VISIBLE", "ok")

	got := finalEnv(Spec{EnvDeny: []string{"ANTHROPIC_*", "GITHUB_*", "AWS_*", "SSH_AUTH_SOCK"}}, nil)
	for _, name := range []string{"ANTHROPIC_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK"} {
		if envHasName(got, name) {
			t.Fatalf("%s leaked through scrubbed env: %v", name, got)
		}
	}
	if !envHasEntry(got, "ISOBOX_VISIBLE=ok") {
		t.Fatalf("non-secret env missing after scrub: %v", got)
	}
}

func TestFinalEnvAllowAndDenyPatterns(t *testing.T) {
	s := Spec{
		Env:      []string{"PATH=/bin", "HOME=/home/me", "APP_TOKEN=secret", "APP_MODE=test", "AWS_REGION=us"},
		EnvAllow: []string{"PATH", "APP_*", "AWS_*"},
		EnvDeny:  []string{"*_TOKEN", "AWS_*"},
	}
	got := finalEnv(s, []string{"ISOBOXFS_MODE=enforce"})
	want := []string{"PATH=/bin", "APP_MODE=test", "ISOBOXFS_MODE=enforce"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("finalEnv()=%v, want %v", got, want)
	}
}

func TestFinalEnvPreservesExplicitEmptyEnv(t *testing.T) {
	got := finalEnv(Spec{Env: []string{}}, nil)
	if got == nil || len(got) != 0 {
		t.Fatalf("explicit empty Env must stay empty, got %#v", got)
	}
}

func TestSpecEnvScrubCapabilityAndValidation(t *testing.T) {
	caps := Spec{Args: []string{"x"}, EnvDeny: []string{"*_TOKEN"}}.Capabilities()
	if !caps.Has(CapEnvScrub) {
		t.Fatalf("EnvDeny must request env.scrub: %v", caps.List())
	}
	if err := (Spec{Args: []string{"x"}, EnvAllow: []string{"["}}).validate(); err == nil {
		t.Fatal("invalid EnvAllow glob should be rejected")
	}
	if err := (Spec{Args: []string{"x"}, EnvDeny: []string{" "}}).validate(); err == nil {
		t.Fatal("empty EnvDeny pattern should be rejected")
	}
}
func TestGvisorOCIConfigUsesScrubbedEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret")
	t.Setenv("ISOBOX_VISIBLE", "ok")
	p, err := compileGvisor(Spec{Args: []string{"echo"}, Net: NetOutbound, EnvDeny: []string{"GITHUB_*"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := gvisorOCIConfig(Spec{Args: []string{"echo"}, Net: NetOutbound, EnvDeny: []string{"GITHUB_*"}}, p.gv, "")
	if envHasName(cfg.Process.Env, "GITHUB_TOKEN") {
		t.Fatalf("GITHUB_TOKEN leaked into OCI env: %v", cfg.Process.Env)
	}
	if !envHasEntry(cfg.Process.Env, "ISOBOX_VISIBLE=ok") {
		t.Fatalf("visible env missing from OCI env: %v", cfg.Process.Env)
	}
}

func TestDockerEnvScrubMaterializesFilteredEnv(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	p, err := compileDockerEphemeral(Spec{
		Args:     []string{"env"},
		Env:      []string{"PATH=/bin", "GITHUB_TOKEN=secret", "APP_MODE=test"},
		EnvAllow: []string{"PATH", "APP_*", "GITHUB_*"},
		EnvDeny:  []string{"GITHUB_*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !argvHasSequence(p.Argv, "--env", "PATH") || !argvHasSequence(p.Argv, "--env", "APP_MODE") {
		t.Fatalf("docker argv missing allowed env names: %v", p.Argv)
	}
	if argvHasSequence(p.Argv, "--env", "GITHUB_TOKEN") || argvHasSequence(p.Argv, "--env", "GITHUB_TOKEN=secret") {
		t.Fatalf("docker argv leaked denied env entry: %v", p.Argv)
	}
}

func TestEnvScrubPlansAdvertiseCapability(t *testing.T) {
	spec := Spec{Args: []string{"echo"}, EnvDeny: []string{"*_TOKEN"}}
	for name, compile := range map[string]func(Spec) (*Plan, error){
		"seatbelt":     compileSeatbelt,
		"gvisor":       compileGvisor,
		"appcontainer": compileAppContainer,
		"docker":       compileDockerEphemeral,
		"docker-runsc": compileDockerRunscEphemeral,
	} {
		t.Run(name, func(t *testing.T) {
			if name == "docker" || name == "docker-runsc" {
				t.Setenv(dockerImageEnv, "alpine")
			}
			p, err := compile(spec)
			if err != nil {
				t.Fatal(err)
			}
			if !p.Uses.Has(CapEnvScrub) {
				t.Fatalf("%s plan missing env.scrub: %v", name, p.Uses.List())
			}
		})
	}
}

func argvHasSequence(argv []string, first, second string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == first && argv[i+1] == second {
			return true
		}
	}
	return false
}

func envHasName(env []string, name string) bool {
	for _, entry := range env {
		if envName(entry) == name {
			return true
		}
	}
	return false
}

func envHasEntry(env []string, want string) bool {
	for _, entry := range env {
		if entry == want {
			return true
		}
	}
	return false
}
