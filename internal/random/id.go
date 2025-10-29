package random

import (
	"crypto/rand"
	"encoding/hex"
)

// NewID returns a 128-bit random identifier encoded as hex.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
