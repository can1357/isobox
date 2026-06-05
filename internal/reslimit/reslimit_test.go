package reslimit

import "testing"

func TestParseCPUs(t *testing.T) {
	cases := []struct {
		in      string
		want    float64
		wantErr bool
	}{
		{"", 0, false},
		{"  ", 0, false},
		{"1", 1, false},
		{"1.5", 1.5, false},
		{"0", 0, false},
		{"-1", 0, true},
		{"abc", 0, true},
		{"NaN", 0, true},
		{"Inf", 0, true},
		{"+Inf", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseCPUs(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseCPUs(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("ParseCPUs(%q)=%v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseMemory(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"1024", 1024, false},
		{"512k", 512 << 10, false},
		{"512kb", 512 << 10, false},
		{"512m", 512 << 20, false},
		{"512MB", 512 << 20, false},
		{"2g", 2 << 30, false},
		{"1t", 1 << 40, false},
		{"4096b", 4096, false},
		{"-5", 0, true},
		{"abc", 0, true},
		{"1.5g", 0, true},                                   // fractional bytes are not allowed
		{"16777216t", 0, true},                              // overflows int64
		{"9223372036854775807", 9223372036854775807, false}, // MaxInt64 bytes, no unit
	}
	for _, tc := range cases {
		got, err := ParseMemory(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseMemory(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("ParseMemory(%q)=%d, want %d", tc.in, got, tc.want)
		}
	}
}
