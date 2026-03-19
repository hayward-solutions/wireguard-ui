package api

import "testing"

func TestValidatePassword(t *testing.T) {
	t.Helper()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid basic", input: "Abcdefg1", wantErr: false},
		{name: "valid with special chars", input: "P@ssw0rd!", wantErr: false},
		{name: "valid alphanumeric", input: "Test1234", wantErr: false},
		{name: "too short", input: "Ab1", wantErr: true},
		{name: "no uppercase", input: "abcdefg1", wantErr: true},
		{name: "no lowercase", input: "ABCDEFG1", wantErr: true},
		{name: "no digit", input: "Abcdefgh", wantErr: true},
		{name: "empty string", input: "", wantErr: true},
		{name: "exactly 8 chars valid", input: "Abcdef1x", wantErr: false},
		{name: "7 chars with all reqs", input: "Abcdef1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePassword(%q): got err=%v, want err=%v", tt.input, err, tt.wantErr)
			}
		})
	}
}
