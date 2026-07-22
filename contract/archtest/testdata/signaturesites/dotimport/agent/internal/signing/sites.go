package signing

import (
	"crypto"

	v1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	. "github.com/manchtools/power-manage/contract/sign"
)

func hiddenResultSigner(key crypto.Signer, result *v1.DeviceSigned) error {
	return SignResult(key, result)
}
