package pki

import (
	"crypto"

	v1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	contractsign "github.com/manchtools/power-manage/contract/sign"
)

type localSignFacade struct{}

func (localSignFacade) SignCommand(any, any) error { return nil }
func (localSignFacade) Sign(any, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

type Authorities struct{}

func (Authorities) SignCommand(key crypto.Signer, command *v1.SignedCommand) error {
	return contractsign.SignCommand(key, command)
}

func shadowedCall() error {
	contractsign := localSignFacade{}
	return contractsign.SignCommand(nil, nil)
}

func unrelatedLocalSign(local localSignFacade) error {
	_, err := local.Sign(nil, nil, crypto.SHA256)
	return err
}

const mentionedCall = "sign.VerifyResult(publicKey, envelope, options)"

// sign.SignResult(deviceKey, envelope) is only prose, not a call site.
