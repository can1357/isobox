//go:build darwin

package isobox

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func runResourceWatchedCommand(ctx context.Context, cmd *exec.Cmd, limits *resourceWatchdogPlan) error {
	if limits == nil || (limits.CPUs <= 0 && limits.MemoryBytes <= 0) {
		return cmd.Run()
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	pgid := cmd.Process.Pid
	done := make(chan struct{})
	watchErr := make(chan error, 1)
	go func() {
		watchErr <- watchDarwinProcessGroup(ctx, pgid, limits, done)
	}()
	waitErr := cmd.Wait()
	close(done)
	if err := <-watchErr; err != nil && waitErr == nil {
		return err
	}
	return waitErr
}

func watchDarwinProcessGroup(ctx context.Context, pgid int, limits *resourceWatchdogPlan, done <-chan struct{}) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	start := time.Now()
	stopped := false
	defer func() {
		if stopped {
			_ = syscall.Kill(-pgid, syscall.SIGCONT)
		}
	}()

	for {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			return ctx.Err()
		case <-ticker.C:
		}

		cpu, rss, err := darwinProcessGroupUsage(pgid)
		if err != nil {
			if errors.Is(err, errDarwinProcessGroupGone) {
				return nil
			}
			return err
		}
		if limits.MemoryBytes > 0 && rss > limits.MemoryBytes {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			return fmt.Errorf("isobox: Seatbelt memory watchdog killed process group %d: sampled rss %d exceeded limit %d", pgid, rss, limits.MemoryBytes)
		}
		if limits.CPUs > 0 {
			allowed := time.Since(start).Seconds() * limits.CPUs
			if overshoot := cpu - allowed; overshoot > 0 {
				pause := time.Duration(overshoot / limits.CPUs * float64(time.Second))
				if pause > 250*time.Millisecond {
					pause = 250 * time.Millisecond
				}
				if pause > 0 {
					_ = syscall.Kill(-pgid, syscall.SIGSTOP)
					stopped = true
					select {
					case <-done:
						return nil
					case <-ctx.Done():
						_ = syscall.Kill(-pgid, syscall.SIGKILL)
						return ctx.Err()
					case <-time.After(pause):
					}
					_ = syscall.Kill(-pgid, syscall.SIGCONT)
					stopped = false
				}
			}
		}
	}
}

var errDarwinProcessGroupGone = errors.New("process group gone")

func darwinProcessGroupUsage(pgid int) (cpuSeconds float64, rssBytes int64, err error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return 0, 0, err
	}
	pageSize := int64(unix.Getpagesize())
	seen := false
	for _, proc := range procs {
		if int(proc.Eproc.Pgid) != pgid {
			continue
		}
		seen = true
		cpuSeconds += float64(proc.Proc.P_rtime.Sec) + float64(proc.Proc.P_rtime.Usec)/1_000_000
		if proc.Eproc.Xrssize > 0 {
			rssBytes += int64(proc.Eproc.Xrssize) * pageSize
		}
	}
	if !seen {
		return 0, 0, errDarwinProcessGroupGone
	}
	return cpuSeconds, rssBytes, nil
}
