package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncryptDecryptV2(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	plaintext := "my-secret-wireguard-key"
	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}
}

func TestV2FormatPrefix(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	encrypted, err := enc.Encrypt("some-value")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if !strings.HasPrefix(encrypted, "enc:v2:") {
		t.Errorf("encrypted value %q does not have enc:v2: prefix", encrypted)
	}
}

func TestV2UniqueCiphertexts(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	plaintext := "same-plaintext"
	a, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt a: %v", err)
	}
	b, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt b: %v", err)
	}

	if a == b {
		t.Error("two encryptions of the same plaintext produced identical ciphertext")
	}
}

func TestDecryptLegacyV1(t *testing.T) {
	passphrase := "test-passphrase"
	plaintext := "legacy-secret-key"

	// Manually produce a v1 encrypted value (SHA-256 + AES-GCM).
	v1Value := encryptV1(t, passphrase, plaintext)

	// Verify it has the v1 prefix and NOT v2.
	if !strings.HasPrefix(v1Value, "enc:") {
		t.Fatalf("v1 value missing enc: prefix: %q", v1Value)
	}
	if strings.HasPrefix(v1Value, "enc:v2:") {
		t.Fatalf("v1 value unexpectedly has v2 prefix: %q", v1Value)
	}

	// Decrypt with the new Encryptor.
	enc, err := NewEncryptor(passphrase)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	decrypted, err := enc.Decrypt(v1Value)
	if err != nil {
		t.Fatalf("Decrypt v1: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptPlaintext(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	value := "not-encrypted-at-all"
	result, err := enc.Decrypt(value)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if result != value {
		t.Errorf("got %q, want %q", result, value)
	}
}

func TestDecryptEmpty(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	result, err := enc.Decrypt("")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if result != "" {
		t.Errorf("got %q, want empty string", result)
	}
}

func TestEncryptEmpty(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	result, err := enc.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if result != "" {
		t.Errorf("got %q, want empty string", result)
	}
}

func TestNilEncryptor(t *testing.T) {
	enc, err := NewEncryptor("")
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	if enc != nil {
		t.Fatal("expected nil encryptor for empty key")
	}

	// Encrypt should pass through.
	encrypted, err := enc.Encrypt("plaintext")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if encrypted != "plaintext" {
		t.Errorf("got %q, want %q", encrypted, "plaintext")
	}

	// Decrypt should pass through.
	decrypted, err := enc.Decrypt("plaintext")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if decrypted != "plaintext" {
		t.Errorf("got %q, want %q", decrypted, "plaintext")
	}
}

func TestWrongKeyFails(t *testing.T) {
	enc1, err := NewEncryptor("correct-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	encrypted, err := enc1.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	enc2, err := NewEncryptor("wrong-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	_, err = enc2.Decrypt(encrypted)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestWrongKeyFailsV1(t *testing.T) {
	v1Value := encryptV1(t, "correct-passphrase", "secret")

	enc, err := NewEncryptor("wrong-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	_, err = enc.Decrypt(v1Value)
	if err == nil {
		t.Error("expected error when decrypting v1 with wrong key")
	}
}

func TestV1ThenV2Roundtrip(t *testing.T) {
	passphrase := "migration-test-key"
	plaintext := "migrating-this-secret"

	// Encrypt with v1 format.
	v1Value := encryptV1(t, passphrase, plaintext)

	// Create encryptor, decrypt v1, re-encrypt as v2.
	enc, err := NewEncryptor(passphrase)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	decrypted, err := enc.Decrypt(v1Value)
	if err != nil {
		t.Fatalf("Decrypt v1: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("v1 decrypt: got %q, want %q", decrypted, plaintext)
	}

	// Re-encrypt (produces v2).
	v2Value, err := enc.Encrypt(decrypted)
	if err != nil {
		t.Fatalf("Encrypt v2: %v", err)
	}
	if !strings.HasPrefix(v2Value, "enc:v2:") {
		t.Fatalf("re-encrypted value missing v2 prefix: %q", v2Value)
	}

	// Decrypt v2.
	final, err := enc.Decrypt(v2Value)
	if err != nil {
		t.Fatalf("Decrypt v2: %v", err)
	}
	if final != plaintext {
		t.Errorf("got %q, want %q", final, plaintext)
	}
}

// encryptV1 produces a legacy v1 encrypted value using SHA-256 key derivation.
func encryptV1(t *testing.T, passphrase, plaintext string) string {
	t.Helper()

	hash := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		t.Fatalf("v1 aes cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("v1 gcm: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("v1 nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return "enc:" + base64.StdEncoding.EncodeToString(ciphertext)
}
