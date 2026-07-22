package signing

import (
	"crypto"

	v1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	contractsign "github.com/manchtools/power-manage/contract/sign"
)

type Profile struct{}

func (Profile) VerifyCommand(key crypto.PublicKey, command *v1.SignedCommand, opts contractsign.VerifyOptions) ([]byte, error) {
	return contractsign.VerifyCommand(key, command, opts)
}

func (Profile) SignResult(key crypto.Signer, result *v1.DeviceSigned) error {
	return contractsign.SignResult(key, result)
}
