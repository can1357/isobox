package isobox

import (
	"fmt"
	"os"
	"path"
	"strings"
)

// EnvAllow lists environment variable name patterns to keep. When empty, every
// variable is eligible unless denied. Patterns are exact names or path.Match-style
// globs over the variable name, such as "*_TOKEN" or "AWS_*".
type EnvAllow []string

// EnvDeny lists environment variable name patterns to remove. Patterns are exact
// names or path.Match-style globs over the variable name, such as "*_SECRET" or
// "SSH_AUTH_SOCK".
type EnvDeny []string

func envScrubActive(s Spec) bool { return len(s.EnvAllow) > 0 || len(s.EnvDeny) > 0 }

func finalEnv(s Spec, extra []string) []string {
	base := s.Env
	if base == nil {
		base = os.Environ()
	}
	base = scrubEnv(base, s.EnvAllow, s.EnvDeny)
	if len(extra) == 0 {
		return cloneEnv(base)
	}
	return appendEnv(base, extra)
}

func cloneEnv(env []string) []string {
	if env == nil {
		return nil
	}
	out := make([]string, len(env))
	copy(out, env)
	return out
}

func scrubEnv(env []string, allow, deny []string) []string {
	if env == nil {
		return nil
	}
	out := make([]string, 0, len(env))
	for _, entry := range env {
		name := envName(entry)
		if len(allow) > 0 && !envNameMatchesAny(name, allow) {
			continue
		}
		if envNameMatchesAny(name, deny) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func validateEnvPatterns(field string, patterns []string) error {
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) == "" {
			return fmt.Errorf("isobox: %s contains an empty pattern", field)
		}
		if _, err := path.Match(pattern, "ISOBOX_ENV_PATTERN_CHECK"); err != nil {
			return fmt.Errorf("isobox: %s pattern %q is invalid: %w", field, pattern, err)
		}
	}
	return nil
}

func envName(entry string) string {
	if i := strings.IndexByte(entry, '='); i >= 0 {
		return entry[:i]
	}
	return entry
}

func envNameMatchesAny(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if ok, err := path.Match(pattern, name); err == nil && ok {
			return true
		}
	}
	return false
}
