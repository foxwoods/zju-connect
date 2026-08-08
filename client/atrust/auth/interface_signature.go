package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// interfaceSignatureKey is a public protocol constant used by the official
// SdpcBroker implementation. It is separate from the per-session anti-MITM
// key used to sign the complete request URI and body.
const interfaceSignatureKey = "oTFBYM#r^we@Hvj4"

func interfaceRequestSignature(random string, body []byte) string {
	if random == "" {
		return ""
	}

	first := hmac.New(sha256.New, []byte(random))
	_, _ = first.Write([]byte(interfaceSignatureKey))
	derivedKey := strings.ToUpper(hex.EncodeToString(first.Sum(nil)))

	second := hmac.New(sha256.New, []byte(derivedKey))
	_, _ = second.Write(body)
	return strings.ToUpper(hex.EncodeToString(second.Sum(nil)))
}
