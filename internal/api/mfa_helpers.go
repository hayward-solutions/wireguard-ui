package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
)

// jsonReader converts a json.RawMessage into an io.Reader for libraries
// that expect to parse from a stream.
func jsonReader(raw json.RawMessage) io.Reader {
	return bytes.NewReader(raw)
}

// encodeBase64URL encodes a byte slice as base64url without padding.
func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
