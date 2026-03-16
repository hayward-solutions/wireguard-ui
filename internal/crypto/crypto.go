package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const encryptedPrefix = "enc:"

// Encryptor handles AES-256-GCM encryption and decryption of sensitive values.
type Encryptor struct {
	gcm cipher.AEAD
}

// NewEncryptor creates a new Encryptor from a passphrase.
// The passphrase is hashed with SHA-256 to derive a 32-byte key.
// Returns nil if the key is empty (encryption disabled).
func NewEncryptor(key string) (*Encryptor, error) {
	if key == "" {
		return nil, nil
	}

	hash := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	return &Encryptor{gcm: gcm}, nil
}

// Encrypt encrypts a plaintext string and returns an "enc:"-prefixed base64 string.
// If the encryptor is nil (encryption disabled), returns the plaintext unchanged.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if e == nil || plaintext == "" {
		return plaintext, nil
	}

	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := e.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encryptedPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts an "enc:"-prefixed string back to plaintext.
// If the value is not prefixed with "enc:", it is returned as-is (plaintext).
// If the encryptor is nil, returns the value unchanged.
func (e *Encryptor) Decrypt(value string) (string, error) {
	if e == nil || !strings.HasPrefix(value, encryptedPrefix) {
		return value, nil
	}

	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, encryptedPrefix))
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	nonceSize := e.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}
