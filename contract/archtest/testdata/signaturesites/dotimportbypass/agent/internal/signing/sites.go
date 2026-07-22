package signing

import (
	"crypto/ecdsa"
	"crypto/rand"

	v1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	. "github.com/manchtools/power-manage/contract/sign"
)

func hiddenResultSigner(result *v1.DeviceSigned) error {
	return SignResult(nil, result)
}

func rawSignatureBypass(key *ecdsa.PrivateKey, digest []byte) {
	_, _ = ecdsa.SignASN1(rand.Reader, key, digest)
}
