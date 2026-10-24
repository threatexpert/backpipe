package main

import (
	"log"
	"net"
)

const businessUDPReadBuffer = 1 << 20

// Called once after creating a business UDP socket. This is a best-effort
// request: the OS may clamp the size, and failure must not prevent forwarding.
func configureBusinessUDPReadBuffer(udp *net.UDPConn, role string) {
	if err := udp.SetReadBuffer(businessUDPReadBuffer); err != nil {
		log.Printf("[%s] UDP receive buffer request failed on %s (requested=%d bytes, continuing with current buffer): %v",
			role, udp.LocalAddr(), businessUDPReadBuffer, err)
	}
}
