package seal

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
)

func TestValidateX25519PublicKey(t *testing.T) {
	valid, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	tests := []struct {
		name string
		key  []byte
		want error
	}{
		{name: "valid", key: valid.PublicKey().Bytes()},
		{name: "empty", want: ErrInvalidX25519PublicKey},
		{name: "short", key: make([]byte, 31), want: ErrInvalidX25519PublicKey},
		{name: "long", key: make([]byte, 33), want: ErrInvalidX25519PublicKey},
		{name: "zero low-order point", key: make([]byte, 32), want: ErrLowOrderX25519PublicKey},
		{name: "one low-order point", key: append([]byte{1}, make([]byte, 31)...), want: ErrLowOrderX25519PublicKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateX25519PublicKey(test.key)
			if test.want == nil {
				if err != nil {
					t.Fatalf("ValidateX25519PublicKey: %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateX25519PublicKey error = %v; want category %v", err, test.want)
			}
		})
	}
}
