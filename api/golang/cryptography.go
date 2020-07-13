package xena

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

func sing(apiSecret string) (nonce int64, payload, sigHex string, err error) {
	var privKeyData []byte
	var privKey *ecdsa.PrivateKey
	var r, s *big.Int

	nonce = time.Now().UnixNano()
	payload = fmt.Sprintf("AUTH%d", nonce)

	privKeyData, err = hex.DecodeString(apiSecret)
	if err != nil {
		err = fmt.Errorf("error: %s on DecodeString", err)
		return
	}

	privKey, err = x509.ParseECPrivateKey(privKeyData)
	if err != nil {
		err = fmt.Errorf("error: %s on ParseECPrivateKey", err)
		return
	}

	digest := sha256.Sum256([]byte(payload))
	r, s, err = ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		err = fmt.Errorf("%s on ecdsa.Sign()", err)
		return
	}
	rPart := r.Bytes()
	sPart := s.Bytes()
	signature := append(make([]byte, 32-len(rPart), 32), rPart...)
	signature = append(signature, append(make([]byte, 32-len(sPart), 32), sPart...)...)
	sigHex = hex.EncodeToString(signature)

	return
}
