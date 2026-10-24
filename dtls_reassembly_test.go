package main

import (
	"bytes"
	"testing"
	"time"
)

func TestDatagramSessionEvictsOldestIncompleteAssemblyForHealthyPacket(t *testing.T) {
	datagramResources.Lock()
	baselineMemory, baselinePieces := datagramResources.memory, datagramResources.pieces
	datagramResources.Unlock()
	server, receiver, _, _ := newTestDatagramPair(t, datagramSessionConfig{}, datagramSessionConfig{}, nil, nil)
	openTestDatagramPair(t, server, receiver)
	first := bytes.Repeat([]byte{'a'}, 1000)
	second := bytes.Repeat([]byte{'b'}, 500)
	want := append(bytes.Clone(first), second...)
	for id := uint64(1); id <= datagramMaxAssemblies; id++ {
		receiver.receiveFragment(testDatagramFrame(id, len(want), 0, first))
	}
	receiver.mu.Lock()
	// Make age ordering deterministic, independent of the system clock's
	// precision and map iteration order, while keeping every packet unexpired.
	base := time.Now().Add(2 * time.Second)
	for id, assembly := range receiver.assemblies {
		assembly.expires = base.Add(time.Duration(id) * time.Millisecond)
	}
	count, memory, pieces := len(receiver.assemblies), receiver.memory, receiver.pieces
	receiver.mu.Unlock()
	if count != 64 || pieces != 64 {
		t.Fatalf("incomplete backlog: assemblies=%d memory=%d pieces=%d", count, memory, pieces)
	}
	// Both pieces arrive within the negotiated record MTU and replay window.
	// A missing piece in an older packet must not block this healthy packet.
	id := uint64(datagramMaxAssemblies + 1)
	receiver.receiveFragment(testDatagramFrame(id, len(want), 0, first))
	receiver.mu.Lock()
	afterCount, afterMemory, afterPieces := len(receiver.assemblies), receiver.memory, receiver.pieces
	_, oldestRetained := receiver.assemblies[1]
	_, newestRetained := receiver.assemblies[id]
	oldestFinished := receiver.finished[1%datagramReplayWindow] == 1
	receiver.mu.Unlock()
	if afterCount != count || afterMemory != memory || afterPieces != pieces || oldestRetained || !newestRetained || !oldestFinished {
		t.Fatalf("oldest replacement/accounting: assemblies=%d memory=%d pieces=%d old=%v new=%v oldFinished=%v", afterCount, afterMemory, afterPieces, oldestRetained, newestRetained, oldestFinished)
	}
	receiver.receiveFragment(testDatagramFrame(id, len(want), len(first), second))
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	packet, err := receiver.ReadPacket(make([]byte, 65535))
	if err != nil || !bytes.Equal(packet, want) {
		t.Fatalf("healthy packet blocked by incomplete backlog: delivered=%d err=%v", len(packet), err)
	}
	// Late pieces of the evicted packet must not allocate a new assembly and
	// evict another packet; the terminal/replay marker suppresses them.
	receiver.mu.Lock()
	beforeLateCount, beforeLateMemory, beforeLatePieces := len(receiver.assemblies), receiver.memory, receiver.pieces
	receiver.mu.Unlock()
	receiver.receiveFragment(testDatagramFrame(1, len(want), len(first), second))
	receiver.receiveFragment(testDatagramFrame(1, len(want), 0, first))
	receiver.mu.Lock()
	afterLateCount, afterLateMemory, afterLatePieces := len(receiver.assemblies), receiver.memory, receiver.pieces
	_, lateRecreated := receiver.assemblies[1]
	receiver.mu.Unlock()
	if lateRecreated || afterLateCount != beforeLateCount || afterLateMemory != beforeLateMemory || afterLatePieces != beforeLatePieces || len(receiver.packets) != 0 {
		t.Fatalf("late pieces recreated evicted packet or changed budget: count=%d memory=%d pieces=%d recreated=%v", afterLateCount, afterLateMemory, afterLatePieces, lateRecreated)
	}
	// The remaining incomplete packets retain their original first pieces.
	receiver.receiveFragment(testDatagramFrame(2, len(want), len(first), second))
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	packet, err = receiver.ReadPacket(make([]byte, 65535))
	if err != nil || !bytes.Equal(packet, want) {
		t.Fatalf("unexpired retained packet could not complete: delivered=%d err=%v", len(packet), err)
	}
	receiver.mu.Lock()
	remaining, usedMemory, usedPieces := len(receiver.assemblies), receiver.memory, receiver.pieces
	receiver.mu.Unlock()
	if remaining != count-2 || usedMemory != (count-2)*(len(want)+datagramAssemblyMemory) || usedPieces != count-2 || usedMemory > datagramSessionMemory || usedPieces > datagramSessionPieces {
		t.Fatalf("completion changed resource accounting: assemblies=%d memory=%d pieces=%d", remaining, usedMemory, usedPieces)
	}
	datagramResources.Lock()
	globalMemory, globalPieces := datagramResources.memory, datagramResources.pieces
	datagramResources.Unlock()
	if globalMemory > datagramGlobalMemory || globalPieces > datagramGlobalPieces {
		t.Fatalf("global budget exceeded: memory=%d pieces=%d", globalMemory, globalPieces)
	}
	receiver.Close()
	server.Close()
	receiver.mu.Lock()
	remaining, usedMemory, usedPieces = len(receiver.assemblies), receiver.memory, receiver.pieces
	receiver.mu.Unlock()
	datagramResources.Lock()
	globalMemory, globalPieces = datagramResources.memory, datagramResources.pieces
	datagramResources.Unlock()
	if remaining != 0 || usedMemory != 0 || usedPieces != 0 || globalMemory != baselineMemory || globalPieces != baselinePieces {
		t.Fatalf("close leaked resources: session=%d/%d/%d global=%d/%d baseline=%d/%d", remaining, usedMemory, usedPieces, globalMemory, globalPieces, baselineMemory, baselinePieces)
	}
}
