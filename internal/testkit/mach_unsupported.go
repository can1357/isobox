//go:build !darwin || !cgo

package testkit

import "errors"

var errMachLookupUnsupported = errors.New("mach bootstrap lookup is only supported on darwin")

func runMachProbe(report *ClientReport, service string) {
	report.Unsupported = errMachLookupUnsupported.Error()
	if service != "" {
		report.AddEvidence("mach.service", service)
	}
}

func hostMachLookupReachable(string) error {
	return errMachLookupUnsupported
}
