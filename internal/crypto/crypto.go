package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// Prefix for legacy v1 encrypted values (SHA-256 derived key).
	v1Prefix = "enc:"
	// Prefix for v2 encrypted values (Argon2id derived key).
	v2Prefix = "enc:v2:"

	// Argon2id parameters (OWASP recommended).
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 4
	argon2KeyLen  = 32

	saltSize = 16
)

// Encryptor handles AES-256-GCM encryption and decryption of sensitive values.
// New values are encrypted with Argon2id key derivation (v2 format).
// Legacy v1 values (SHA-256 derived key) are transparently decrypted.
type Encryptor struct {
	passphrase []byte      // raw passphrase for Argon2id derivation
	legacyGCM  cipher.AEAD // SHA-256-derived GCM for decrypting v1 data
}

// NewEncryptor creates a new Encryptor from a passphrase.
// Returns nil if the key is empty (encryption disabled).
func NewEncryptor(key string) (*Encryptor, error) {
	if key == "" {
		return nil, nil
	}

	// Derive legacy GCM for v1 backward compatibility.
	hash := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	legacyGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	return &Encryptor{
		passphrase: []byte(key),
		legacyGCM:  legacyGCM,
	}, nil
}

// Encrypt encrypts a plaintext string using Argon2id key derivation and AES-256-GCM.
// Returns an "enc:v2:"-prefixed base64 string.
// If the encryptor is nil (encryption disabled), returns the plaintext unchanged.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if e == nil || plaintext == "" {
		return plaintext, nil
	}

	// Generate random salt for Argon2id.
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Derive key via Argon2id.
	key := deriveKey(e.passphrase, salt)

	// Encrypt with AES-256-GCM.
	ciphertext, err := encryptWithKey(key, []byte(plaintext))
	if err != nil {
		return "", err
	}

	// Payload: salt || nonce || ciphertext+tag
	payload := make([]byte, 0, saltSize+len(ciphertext))
	payload = append(payload, salt...)
	payload = append(payload, ciphertext...)

	return v2Prefix + base64.StdEncoding.EncodeToString(payload), nil
}

// Decrypt decrypts an encrypted string back to plaintext.
// Supports both v2 (Argon2id) and legacy v1 (SHA-256) formats.
// If the value has no encryption prefix, it is returned as-is (plaintext).
// If the encryptor is nil, returns the value unchanged.
func (e *Encryptor) Decrypt(value string) (string, error) {
	if e == nil {
		return value, nil
	}

	// Check v2 first (more specific prefix).
	if strings.HasPrefix(value, v2Prefix) {
		return e.decryptV2(strings.TrimPrefix(value, v2Prefix))
	}

	// Check legacy v1.
	if strings.HasPrefix(value, v1Prefix) {
		return e.decryptV1(strings.TrimPrefix(value, v1Prefix))
	}

	// No prefix — plaintext passthrough.
	return value, nil
}

// decryptV2 decrypts a v2 formatted value (Argon2id derived key).
func (e *Encryptor) decryptV2(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	if len(data) < saltSize+12 { // salt + minimum nonce size
		return "", fmt.Errorf("ciphertext too short")
	}

	salt := data[:saltSize]
	remainder := data[saltSize:]

	// Derive key via Argon2id using the stored salt.
	key := deriveKey(e.passphrase, salt)

	plaintext, err := decryptWithKey(key, remainder)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// decryptV1 decrypts a legacy v1 formatted value (SHA-256 derived key).
func (e *Encryptor) decryptV1(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	nonceSize := e.legacyGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := e.legacyGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// deriveKey derives a 32-byte encryption key from a passphrase and salt using Argon2id.
func deriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

// encryptWithKey encrypts plaintext with a raw 32-byte AES-256-GCM key.
// Returns nonce || ciphertext+tag.
func encryptWithKey(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptWithKey decrypts data (nonce || ciphertext+tag) with a raw 32-byte AES-256-GCM key.
func decryptWithKey(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
