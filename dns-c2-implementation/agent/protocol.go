package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// randomHex8 returns a random 8-character lowercase hex string suitable for
// use as a task ID or agent ID component.
func randomHex8() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback: use a fixed value so we never panic; the caller will
		// notice stale IDs in logs if this ever fires.
		return "deadbeef"
	}
	return fmt.Sprintf("%08x", binary.LittleEndian.Uint32(b[:]))
}

// xorCrypt applies a repeating-key XOR over data using key (4 bytes, repeated).
// Encryption and decryption are the same operation.
func xorCrypt(data []byte, key []byte) []byte {
	if len(key) == 0 {
		out := make([]byte, len(data))
		copy(out, data)
		return out
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// packU16LE serialises v as a 2-byte little-endian value.
func packU16LE(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

// packU32LE serialises v as a 4-byte little-endian value.
func packU32LE(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// readU16LE reads a 2-byte little-endian uint16 from the start of b.
// The caller is responsible for ensuring len(b) >= 2.
func readU16LE(b []byte) uint16 {
	return binary.LittleEndian.Uint16(b[:2])
}

// readU32LE reads a 4-byte little-endian uint32 from the start of b.
// The caller is responsible for ensuring len(b) >= 4.
func readU32LE(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b[:4])
}
