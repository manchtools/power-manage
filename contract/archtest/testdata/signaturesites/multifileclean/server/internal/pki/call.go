package pki

import "crypto"

func callPackageLocalSigner(signer packageLocalSigner) error {
	_, err := signer.Sign(nil, nil, crypto.SHA256)
	return err
}
