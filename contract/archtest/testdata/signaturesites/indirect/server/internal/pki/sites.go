package pki

import (
	"crypto"

	v1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	sig "github.com/manchtools/power-manage/contract/sign"
)

var hiddenCommandSigner = sig.SignCommand

func parenthesizedResultVerifier(key crypto.PublicKey, result *v1.DeviceSigned, opts sig.ResultVerifyOptions) ([]byte, error) {
	return (sig.VerifyResult)(key, result, opts)
}
