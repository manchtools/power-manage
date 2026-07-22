package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"math/big"

	v1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	contractsign "github.com/manchtools/power-manage/contract/sign"
)

func bypassPreimages(command *v1.SignedCommand, result *v1.DeviceSigned) {
	_, _ = contractsign.CommandPreimage(command)
	_, _ = contractsign.ResultPreimage(result)
}

func bypassDomains(commandType, resultType string) {
	_, _ = contractsign.CommandDomain(commandType)
	_, _ = contractsign.ResultDomain(resultType)
	_ = contractsign.ActionSignatureDomain
}

func rawECDSA(key *ecdsa.PrivateKey, digest, signature []byte) {
	_, _ = ecdsa.SignASN1(rand.Reader, key, digest)
	_ = ecdsa.VerifyASN1(&key.PublicKey, digest, signature)
	_, _, _ = ecdsa.Sign(rand.Reader, key, digest)
	_ = ecdsa.Verify(&key.PublicKey, digest, big.NewInt(1), big.NewInt(1))
}

func rawRSA(key *rsa.PrivateKey, digest, signature []byte) {
	_, _ = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	_ = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest, signature)
}

func rawSigner(signer crypto.Signer, digest []byte) {
	_, _ = signer.Sign(rand.Reader, digest, crypto.SHA256)
}

func addressableRSAValue(key rsa.PrivateKey, digest []byte) {
	_, _ = key.Sign(rand.Reader, digest, crypto.SHA256)
}

func rawMessageSigning(signer crypto.MessageSigner, message []byte) {
	_, _ = crypto.SignMessage(signer, rand.Reader, message, crypto.Hash(0))
	_, _ = signer.SignMessage(rand.Reader, message, crypto.Hash(0))
}

func rawEd25519Options(publicKey ed25519.PublicKey, message, signature []byte) {
	_ = ed25519.VerifyWithOptions(publicKey, message, signature, &ed25519.Options{})
}
