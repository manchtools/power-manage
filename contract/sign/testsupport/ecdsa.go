// Package testsupport provides adversarial signing-key fixtures shared across
// contract consumers.
package testsupport

import (
	"crypto/ecdsa"
	"math/big"
	"reflect"
)

// TestingT is the test surface needed by ECDSAPrivateKeyWithScalar.
type TestingT interface {
	Helper()
	Fatal(args ...any)
}

// ECDSAPrivateKeyWithScalar constructs intentionally invalid ECDSA keys that
// the standard parsers correctly refuse to create.
func ECDSAPrivateKeyWithScalar(t TestingT, public ecdsa.PublicKey, scalar []byte) *ecdsa.PrivateKey {
	t.Helper()
	key := &ecdsa.PrivateKey{PublicKey: public}
	field := reflect.ValueOf(key).Elem().FieldByName("D")
	if !field.IsValid() || !field.CanSet() {
		t.Fatal("ecdsa.PrivateKey scalar field D is unavailable to the adversarial test fixture")
	}
	if scalar == nil {
		field.Set(reflect.Zero(field.Type()))
	} else {
		field.Set(reflect.ValueOf(new(big.Int).SetBytes(scalar)))
	}
	return key
}
