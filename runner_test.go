package isobox

import (
	"os"
	"testing"
)

func TestStdioZeroValueDefaultsToProcessFiles(t *testing.T) {
	in, out, errw := Stdio{}.orDefaults()
	if in != os.Stdin {
		t.Fatalf("zero-value stdin default = %#v, want os.Stdin", in)
	}
	if out != os.Stdout {
		t.Fatalf("zero-value stdout default = %#v, want os.Stdout", out)
	}
	if errw != os.Stderr {
		t.Fatalf("zero-value stderr default = %#v, want os.Stderr", errw)
	}
}
