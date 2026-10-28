package main

import (
	"io"
	"net"
	"sync"
	"time"
)

func relay(c1, c2 net.Conn) {
	relayWithDrainTimeout(c1, c2, 30*time.Second)
}

// EOF preserves the reverse direction for a bounded drain. Errors terminate
// both directions immediately. The drain timer also covers blocked Write and
// CloseWrite calls, rather than relying only on the remaining reader's deadline.
func relayWithDrainTimeout(c1, c2 net.Conn, drain time.Duration) {
	type event struct {
		finished bool
		err      error
	}
	events := make(chan event, 4)
	var workers sync.WaitGroup
	pipe := func(dst, src net.Conn) {
		defer workers.Done()
		_, err := io.Copy(dst, src)
		// Notify before CloseWrite: flushing a half-close can itself block.
		events <- event{err: err}
		if err == nil {
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				err = cw.CloseWrite()
			}
		}
		events <- event{finished: true, err: err}
	}
	workers.Add(2)
	go pipe(c1, c2)
	go pipe(c2, c1)

	var timer *time.Timer
	var timeout <-chan time.Time
	force := false
draining:
	for finished := 0; finished < 2; {
		select {
		case e := <-events:
			if e.err != nil {
				force = true
				break draining
			}
			if timer == nil {
				timer = time.NewTimer(drain)
				timeout = timer.C
			}
			if e.finished {
				finished++
			}
		case <-timeout:
			force = true
			break draining
		}
	}
	if timer != nil {
		timer.Stop()
	}
	if force {
		// Interrupt both reads and writes before closing transports that may
		// briefly wait for a graceful shutdown acknowledgment.
		c1.SetDeadline(time.Now())
		c2.SetDeadline(time.Now())
	}
	// Close concurrently so one transport's graceful close cannot delay
	// releasing the other endpoint. Join both closes and forwarding workers.
	var closing sync.WaitGroup
	closing.Add(2)
	for _, c := range []net.Conn{c1, c2} {
		go func() { defer closing.Done(); c.Close() }()
	}
	closing.Wait()
	workers.Wait()
}
