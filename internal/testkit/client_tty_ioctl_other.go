//go:build !darwin && !linux

package testkit

func runTTYIoctlProbe(report *ClientReport) {
	report.Unsupported = "TIOCSTI probe is only defined on Darwin/Linux"
}
