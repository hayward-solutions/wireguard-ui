package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// HashAPIToken computes HMAC-SHA256(key, rawToken) and returns the hex-encoded
// digest. Using a keyed HMAC instead of bare SHA-256 provides domain separation
// and resistance to precomputation (rainbow table) attacks.
func HashAPIToken(key []byte, rawToken string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(rawToken))
	return hex.EncodeToString(mac.Sum(nil))
}
