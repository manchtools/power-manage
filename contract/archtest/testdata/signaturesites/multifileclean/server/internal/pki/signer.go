package pki

import "crypto"

type packageLocalSigner struct{}

func (packageLocalSigner) Sign(any, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}
