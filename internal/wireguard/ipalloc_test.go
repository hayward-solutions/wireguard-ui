package wireguard

import (
	"fmt"
	"testing"
)

func TestAllocateIP(t *testing.T) {
	tests := []struct {
		name          string
		subnet        string
		usedAddresses []string
		want          string
		wantErr       bool
	}{
		{
			name:          "empty used list returns first free IP after server",
			subnet:        "10.0.0.1/24",
			usedAddresses: nil,
			want:          "10.0.0.2/32",
		},
		{
			name:          "skips single used address",
			subnet:        "10.0.0.1/24",
			usedAddresses: []string{"10.0.0.2/32"},
			want:          "10.0.0.3/32",
		},
		{
			name:          "skips multiple used addresses with mixed formats",
			subnet:        "10.0.0.1/24",
			usedAddresses: []string{"10.0.0.2", "10.0.0.3/32"},
			want:          "10.0.0.4/32",
		},
		{
			name:          "network-address subnet returns first usable IP",
			subnet:        "10.0.0.0/24",
			usedAddresses: nil,
			want:          "10.0.0.1/32",
		},
		{
			name:          "/30 subnet returns first free after server",
			subnet:        "10.0.0.1/30",
			usedAddresses: nil,
			want:          "10.0.0.2/32",
		},
		{
			name:          "/30 subnet all usable IPs taken returns error",
			subnet:        "10.0.0.1/30",
			usedAddresses: []string{"10.0.0.2/32", "10.0.0.3/32"},
			want:          "",
			wantErr:       true,
		},
		{
			name:          "invalid subnet returns error",
			subnet:        "not-a-subnet",
			usedAddresses: nil,
			want:          "",
			wantErr:       true,
		},
		{
			name:          "skips broadcast address 255",
			subnet:        "10.0.0.1/24",
			usedAddresses: func() []string {
				var addrs []string
				for i := 2; i < 255; i++ {
					addrs = append(addrs, fmt.Sprintf("10.0.0.%d", i))
				}
				return addrs
			}(),
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AllocateIP(tt.subnet, tt.usedAddresses)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AllocateIP() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("AllocateIP() got %q, want %q", got, tt.want)
			}
		})
	}
}
