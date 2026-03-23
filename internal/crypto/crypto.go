package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// Prefix for legacy v1 encrypted values (SHA-256 derived key).
	v1Prefix = "enc:"
	// Prefix for legacy v2 encrypted values (Argon2id derived key).
	v2Prefix = "enc:v2:"
	// Prefix for v3 encrypted values (HKDF derived key).
	v3Prefix = "enc:v3:"

	// Argon2id parameters for legacy v2 decryption.
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 4
	argon2KeyLen  = 32

	saltSize = 16
	keyLen   = 32
)

// Encryptor handles AES-256-GCM encryption and decryption of sensitive values.
//
// New values are encrypted with HKDF key derivation (v3 format), which derives
// a unique per-record key from a master key using a random salt. The master key
// is derived once at construction time via HKDF-Extract, making encrypt/decrypt
// operations fast (single HMAC vs. 64 MiB Argon2id per call).
//
// Legacy v1 (SHA-256) and v2 (Argon2id) values are transparently decrypted.
type Encryptor struct {
	masterKey  []byte      // HKDF-Extract derived master key (32 bytes)
	passphrase []byte      // raw passphrase for legacy Argon2id v2 decryption
	legacyGCM  cipher.AEAD // SHA-256-derived GCM for decrypting v1 data
}

// NewEncryptor creates a new Encryptor from a passphrase.
// Returns nil if the key is empty (encryption disabled).
func NewEncryptor(key string) (*Encryptor, error) {
	if key == "" {
		return nil, nil
	}

	// Derive master key via HKDF-Extract for v3 encryption.
	// The passphrase is already high-entropy (validated to be 16+ chars at startup),
	// so HKDF is appropriate here (unlike Argon2id which is for weak passwords).
	masterKey, err := deriveMasterKey([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("derive master key: %w", err)
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
		masterKey:  masterKey,
		passphrase: []byte(key),
		legacyGCM:  legacyGCM,
	}, nil
}

// Encrypt encrypts a plaintext string using HKDF key derivation and AES-256-GCM.
// Returns an "enc:v3:"-prefixed base64 string.
// If the encryptor is nil (encryption disabled), returns the plaintext unchanged.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if e == nil || plaintext == "" {
		return plaintext, nil
	}

	// Generate random salt for HKDF-Expand.
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Derive per-record key via HKDF-Expand.
	key, err := deriveRecordKey(e.masterKey, salt)
	if err != nil {
		return "", fmt.Errorf("derive record key: %w", err)
	}

	// Encrypt with AES-256-GCM.
	ciphertext, err := encryptWithKey(key, []byte(plaintext))
	if err != nil {
		return "", err
	}

	// Payload: salt || nonce || ciphertext+tag
	payload := make([]byte, 0, saltSize+len(ciphertext))
	payload = append(payload, salt...)
	payload = append(payload, ciphertext...)

	return v3Prefix + base64.StdEncoding.EncodeToString(payload), nil
}

// Decrypt decrypts an encrypted string back to plaintext.
// Supports v3 (HKDF), v2 (Argon2id), and legacy v1 (SHA-256) formats.
// If the value has no encryption prefix, it is returned as-is (plaintext).
// If the encryptor is nil, returns the value unchanged.
func (e *Encryptor) Decrypt(value string) (string, error) {
	if e == nil {
		return value, nil
	}

	// Check v3 first (most specific prefix).
	if strings.HasPrefix(value, v3Prefix) {
		return e.decryptV3(strings.TrimPrefix(value, v3Prefix))
	}

	// Check v2 (Argon2id).
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

// decryptV3 decrypts a v3 formatted value (HKDF derived key).
func (e *Encryptor) decryptV3(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	if len(data) < saltSize+12 { // salt + minimum nonce size
		return "", fmt.Errorf("ciphertext too short")
	}

	salt := data[:saltSize]
	remainder := data[saltSize:]

	// Derive per-record key via HKDF-Expand using the stored salt.
	key, err := deriveRecordKey(e.masterKey, salt)
	if err != nil {
		return "", fmt.Errorf("derive record key: %w", err)
	}

	plaintext, err := decryptWithKey(key, remainder)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
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
	key := deriveKeyArgon2(e.passphrase, salt)

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

// deriveMasterKey derives a 32-byte master key from a passphrase using HKDF-Extract.
func deriveMasterKey(passphrase []byte) ([]byte, error) {
	// Use HKDF-Extract with a fixed salt to derive a pseudorandom key.
	// The fixed salt provides domain separation; the passphrase is already
	// high-entropy so a random salt is not required.
	hkdfSalt := []byte("wireguard-ui-encryption-v3")
	r := hkdf.New(sha256.New, passphrase, hkdfSalt, []byte("master-key"))
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// deriveRecordKey derives a 32-byte per-record encryption key from a master key
// and a random salt using HKDF-Expand. This is fast (single HMAC operation).
func deriveRecordKey(masterKey, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, masterKey, salt, []byte("record-key"))
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// deriveKeyArgon2 derives a 32-byte encryption key from a passphrase and salt
// using Argon2id. Used only for decrypting legacy v2 data.
func deriveKeyArgon2(passphrase, salt []byte) []byte {
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
