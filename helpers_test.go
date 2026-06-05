package isobox

import "strings"

func argvIndex(argv []string, want string) int {
	for i, a := range argv {
		if a == want {
			return i
		}
	}
	return -1
}

func argvHas(argv []string, want string) bool { return argvIndex(argv, want) >= 0 }

func profileHas(profile, frag string) bool { return strings.Contains(profile, frag) }
