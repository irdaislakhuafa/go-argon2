package argon2

import "testing"

func TestArgon2(t *testing.T) {
	type test struct {
		Name      string
		IsWantErr bool
		WantErr   error
	}

	tests := []test{
		{
			Name: "hash with argon2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if tt.IsWantErr {

			}
		})
	}
}
