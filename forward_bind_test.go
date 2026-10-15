package main

import (
	"net"
	"strings"
	"testing"
)

func TestForwardListenersBindTCPAndUDPOnSamePort(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	reserved.Close()
	entries := []entryConfig{
		{endpoint: endpoint{scheme: "udp", address: address, target: "charon:500"}},
		{endpoint: endpoint{scheme: "tcp", address: address, target: "web:80"}},
	}
	pool, listeners, err := bindServerListeners(entries, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, ln := range listeners {
		defer ln.Close()
		if ln.Addr().String() != address {
			t.Fatalf("bound %s, want %s", ln.Addr(), address)
		}
	}
	if listeners[0].udp == nil || listeners[1].tcp == nil {
		t.Fatal("listeners did not bind their requested transport")
	}
}

func TestMixedListenerBindFailureReleasesAllTransports(t *testing.T) {
	for _, duplicate := range []string{"udp", "tcp"} {
		t.Run(duplicate, func(t *testing.T) {
			reserved, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := reserved.Addr().String()
			reserved.Close()
			poolReserved, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			poolAddress := poolReserved.Addr().String()
			poolReserved.Close()
			entries := []entryConfig{
				{endpoint: endpoint{scheme: "udp", address: address, target: "charon:500"}},
				{endpoint: endpoint{scheme: "tcp", address: address, target: "web:80"}},
				{endpoint: endpoint{scheme: duplicate, address: address, target: "other:80"}},
			}
			pool, listeners, err := bindServerListeners(entries, poolAddress)
			if err == nil {
				pool.Close()
				for _, ln := range listeners {
					ln.Close()
				}
				t.Fatal("duplicate transport/address did not fail")
			}
			if !strings.Contains(err.Error(), "entry 3") {
				t.Fatal(err)
			}
			for _, addr := range []string{address, poolAddress} {
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					t.Fatalf("TCP port left bound after failure: %v", err)
				}
				ln.Close()
			}
			udpAddress, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			udp, err := net.ListenUDP("udp", udpAddress)
			if err != nil {
				t.Fatalf("UDP port left bound after failure: %v", err)
			}
			udp.Close()
		})
	}
}
