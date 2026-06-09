// Package reslimit parses human-friendly CPU and memory limit strings into the
// numeric values isobox.Spec expects. It is shared by the isobox and isobox-sshd
// command-line tools so both accept identical syntax.
package reslimit

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ParseCPUs reads a logical-core count (fractional allowed). The empty string
// means "no limit" and returns 0.
func ParseCPUs(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("invalid cpus %q (want a non-negative number like 1.5)", s)
	}
	return v, nil
}

// ParsePIDs reads a process/task count. The empty string means "no limit" and
// returns 0.
func ParsePIDs(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid pids %q (want a non-negative integer)", s)
	}
	return v, nil
}

// ParseMemory reads a byte count with an optional binary unit suffix
// (k/kb, m/mb, g/gb, t/tb; 1024-based). A bare number is bytes. The empty
// string means "no limit" and returns 0.
func ParseMemory(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	lower := strings.ToLower(s)
	mult := int64(1)
	switch {
	case strings.HasSuffix(lower, "tb"):
		mult, lower = 1<<40, strings.TrimSuffix(lower, "tb")
	case strings.HasSuffix(lower, "gb"):
		mult, lower = 1<<30, strings.TrimSuffix(lower, "gb")
	case strings.HasSuffix(lower, "mb"):
		mult, lower = 1<<20, strings.TrimSuffix(lower, "mb")
	case strings.HasSuffix(lower, "kb"):
		mult, lower = 1<<10, strings.TrimSuffix(lower, "kb")
	case strings.HasSuffix(lower, "t"):
		mult, lower = 1<<40, strings.TrimSuffix(lower, "t")
	case strings.HasSuffix(lower, "g"):
		mult, lower = 1<<30, strings.TrimSuffix(lower, "g")
	case strings.HasSuffix(lower, "m"):
		mult, lower = 1<<20, strings.TrimSuffix(lower, "m")
	case strings.HasSuffix(lower, "k"):
		mult, lower = 1<<10, strings.TrimSuffix(lower, "k")
	case strings.HasSuffix(lower, "b"):
		lower = strings.TrimSuffix(lower, "b")
	}
	v, err := strconv.ParseInt(strings.TrimSpace(lower), 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid memory %q (want bytes or a size like 512m, 2g)", s)
	}
	if mult > 1 && v > (math.MaxInt64/mult) {
		return 0, fmt.Errorf("invalid memory %q (want bytes or a size like 512m, 2g)", s)
	}
	return v * mult, nil
}
