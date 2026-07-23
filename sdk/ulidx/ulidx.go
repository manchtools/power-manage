// Package ulidx mints canonical, time-sortable ULIDs with checked entropy.
package ulidx

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	encodedLength  = 26
	maxTimestampMS = 1<<48 - 1
)

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var randomReader io.Reader = rand.Reader

// New mints one ULID using crypto/rand.
func New(now time.Time) (string, error) {
	return NewWithReader(now, randomReader)
}

// NewWithReader mints one ULID using an explicit checked entropy source.
func NewWithReader(now time.Time, entropy io.Reader) (string, error) {
	if entropy == nil {
		return "", errors.New("ulidx: entropy source is nil")
	}
	timestamp := now.UnixMilli()
	if timestamp < 0 || timestamp > maxTimestampMS {
		return "", errors.New("ulidx: time is outside the 48-bit timestamp range")
	}
	var raw [16]byte
	value := uint64(timestamp)
	for index := 5; index >= 0; index-- {
		raw[index] = byte(value)
		value >>= 8
	}
	if _, err := io.ReadFull(entropy, raw[6:]); err != nil {
		return "", fmt.Errorf("ulidx: read entropy: %w", err)
	}
	return encode(raw), nil
}

func encode(raw [16]byte) string {
	encoded := make([]byte, encodedLength)
	for output := range encoded {
		var value byte
		for offset := range 5 {
			value <<= 1
			bit := output*5 + offset - 2
			if bit >= 0 && bit < len(raw)*8 {
				value |= (raw[bit/8] >> (7 - bit%8)) & 1
			}
		}
		encoded[output] = alphabet[value]
	}
	return string(encoded)
}
