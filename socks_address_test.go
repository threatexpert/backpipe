package main

import (
	"bytes"
	"testing"
)

func TestSOCKSEmptyDomain(t *testing.T) {
	for _, tc := range []struct {
		name       string
		address    []byte
		allowEmpty bool
		wantError  bool
	}{
		{"associate", []byte{0, 0x12, 0x34}, true, false},
		{"connect", []byte{0, 0, 0}, false, true},
		{"missing-port", []byte{0}, true, true},
		{"partial-port", []byte{0, 0}, true, true},
		{"whitespace", []byte{1, ' ', 0, 0}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := bytes.NewReader(tc.address)
			host, port, err := readSOCKSAddress(r, 3, tc.allowEmpty)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, wantError = %v", err, tc.wantError)
			}
			if !tc.wantError && (host != "0.0.0.0" || port != 0x1234 || r.Len() != 0) {
				t.Fatalf("host=%q port=%d unread=%d", host, port, r.Len())
			}
		})
	}
	if _, _, _, err := parseUDPPacket([]byte{0, 0, 0, 3, 0, 0, 53, 'x'}); err == nil {
		t.Fatal("UDP datagram with an empty destination domain was accepted")
	}
}
