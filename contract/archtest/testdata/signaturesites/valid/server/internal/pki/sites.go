package pki

import (
	"crypto"

	v1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	sig "github.com/manchtools/power-manage/contract/sign"
)

type Authorities struct{}

func (Authorities) SignCommand(key crypto.Signer, command *v1.SignedCommand) error {
	return sig.SignCommand(key, command)
}

type DERResultVerifier struct{}

func (DERResultVerifier) VerifyResult(key crypto.PublicKey, result *v1.DeviceSigned, opts sig.ResultVerifyOptions) ([]byte, error) {
	return sig.VerifyResult(key, result, opts)
}
