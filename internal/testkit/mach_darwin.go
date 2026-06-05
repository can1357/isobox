//go:build darwin

package testkit

/*
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdlib.h>

static kern_return_t isobox_bootstrap_look_up(const char *service_name, mach_port_t *service_port) {
	return bootstrap_look_up(bootstrap_port, service_name, service_port);
}

static kern_return_t isobox_mach_port_deallocate(mach_port_t port) {
	return mach_port_deallocate(mach_task_self(), port);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

func runMachProbe(report *ClientReport, service string) {
	if err := lookupMachService(service); err != nil {
		report.AddCheck("lookup", false, err)
	} else {
		report.AddCheck("lookup", true, nil)
	}
	report.AddEvidence("mach.service", service)
}

func hostMachLookupReachable(service string) error {
	return lookupMachService(service)
}

func lookupMachService(service string) error {
	if service == "" {
		return errors.New("mach probe requires --mach-service")
	}

	name := C.CString(service)
	if name == nil {
		return errors.New("allocating mach service name failed")
	}
	defer C.free(unsafe.Pointer(name))

	var port C.mach_port_t
	kr := C.isobox_bootstrap_look_up(name, &port)
	if kr != C.KERN_SUCCESS {
		return fmt.Errorf("bootstrap_look_up: %d", int(kr))
	}
	_ = C.isobox_mach_port_deallocate(port)
	return nil
}
