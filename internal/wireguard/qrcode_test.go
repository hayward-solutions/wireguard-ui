package wireguard

import (
	"testing"
)

func TestGenerateQRCode(t *testing.T) {
	config := "[Interface]\nPrivateKey = testkey\nAddress = 10.0.0.2/32\n"

	got, err := GenerateQRCode(config, 256)
	if err != nil {
		t.Fatalf("GenerateQRCode() error = %v", err)
	}
	if len(got) == 0 {
		t.Fatal("GenerateQRCode() returned empty bytes")
	}

	// PNG magic bytes: 0x89 0x50 0x4E 0x47
	if len(got) < 4 {
		t.Fatalf("GenerateQRCode() output too short: got %d bytes", len(got))
	}
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47}
	for i, b := range pngMagic {
		if got[i] != b {
			t.Errorf("GenerateQRCode() PNG magic byte[%d] got 0x%02X, want 0x%02X", i, got[i], b)
		}
	}
}

func TestGenerateQRCode_EmptyInput(t *testing.T) {
	_, err := GenerateQRCode("", 256)
	if err == nil {
		t.Error("GenerateQRCode() with empty input got nil error, want error")
	}
}

func TestGenerateQRCode_DifferentSizes(t *testing.T) {
	config := "test-config-data"

	small, err := GenerateQRCode(config, 256)
	if err != nil {
		t.Fatalf("GenerateQRCode(256) error = %v", err)
	}

	large, err := GenerateQRCode(config, 512)
	if err != nil {
		t.Fatalf("GenerateQRCode(512) error = %v", err)
	}

	if len(small) == len(large) {
		t.Errorf("GenerateQRCode() size 256 and 512 produced same length output: %d bytes", len(small))
	}
}
