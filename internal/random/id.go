package random

import (
	"crypto/rand"
	"encoding/hex"
)

// NewID returns a version 4 UUID string.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}

	// Set version (4) and variant (10) bits per RFC 4122.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	var dst [32]byte
	hex.Encode(dst[:], b[:])

	return string(dst[0:8]) + "-" +
		string(dst[8:12]) + "-" +
		string(dst[12:16]) + "-" +
		string(dst[16:20]) + "-" +
		string(dst[20:32])
}
