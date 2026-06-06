package isobox

import "fmt"

func selectBackendForSpec(goos string, s Spec) (Backend, error) {
	candidates := backendCandidatesForGOOS(goos)
	if len(candidates) == 0 {
		return "", fmt.Errorf("isobox: no sandbox backend for GOOS %q (supported: darwin, linux, windows)", goos)
	}
	requested := s.Capabilities()
	for _, b := range candidates {
		if requested.Sub(CapsOf(b)).Len() == 0 {
			return b, nil
		}
	}
	fallback := candidates[0]
	return fallback, nil
}

func backendCandidatesForGOOS(goos string) []Backend {
	switch goos {
	case "darwin":
		return []Backend{BackendSeatbelt, BackendDockerRunscEphemeral, BackendDockerEphemeral}
	case "linux":
		return []Backend{BackendGvisor, BackendDockerRunscEphemeral, BackendDockerEphemeral}
	case "windows":
		return []Backend{BackendAppContainer}
	default:
		return nil
	}
}
