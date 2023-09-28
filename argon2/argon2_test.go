package argon2

import (
	"errors"
	"testing"
)

const (
	Hash = (iota + 1)
	Compare
)

func TestArgon2(t *testing.T) {
	type test struct {
		Name         string
		Mode         int
		Password     string
		PasswordHash string
		IsWantMatch  bool
		IsWantErr    bool
		WantErr      error
	}

	tests := []test{
		{
			Name:      "hash with argon2",
			Mode:      Hash,
			Password:  "password",
			IsWantErr: false,
			WantErr:   nil,
		},
		{
			Name:         "compare password match",
			Mode:         Compare,
			Password:     "password",
			PasswordHash: "$argon2id$v=19$m=4096,t=3,p=1$pm9zF0rXyAIMMdfbTx28VA$hixSAozskGrRcvtBDg33e4K4nT48y0ih2I4e4LDtLBw",
			IsWantMatch:  true,
			IsWantErr:    false,
			WantErr:      nil,
		},
		{
			Name:         "argon2 incompatible",
			Mode:         Compare,
			Password:     "password",
			PasswordHash: "$argon2id$v=18$m=4096,t=3,p=1$pm9zF0rXyAIMMdfbTx28VA$hixSAozskGrRcvtBDg33e4K4nT48y0ih2I4e4LDtLBw",
			IsWantMatch:  false,
			IsWantErr:    true,
			WantErr:      ErrIncompatibleArgon2Version,
		},
		{
			Name:         "argon2 invalid format",
			Mode:         Compare,
			Password:     "password",
			PasswordHash: "$$pm9zF0rXyAIMMdfbTx28VA$hixSAozskGrRcvtBDg33e4K4nT48y0ih2I4e4LDtLBw",
			IsWantMatch:  false,
			IsWantErr:    true,
			WantErr:      ErrInvalidHashLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			switch tt.Mode {
			case Hash:
				hashed, err := HashArgon2([]byte(tt.Password))
				if tt.IsWantErr {
					if err == nil {
						t.Fatalf("expected error but no error provided")
					}

					if !errors.Is(err, tt.WantErr) {
						t.Fatalf("expected error '%v' but get error '%v'", tt.WantErr, err)
					}
				} else if !tt.IsWantErr {
					if err != nil {
						t.Fatalf("expected no error but get error '%v'", err)
					}
				}

				if hashed == tt.Password {
					t.Fatalf("argon2 hash not working")
				}
			case Compare:
				isMatch, err := CompareArgon2(tt.Password, tt.PasswordHash)
				if tt.IsWantErr {
					if err == nil {
						t.Fatalf("expected error but no error provided")
					}
					if !errors.Is(err, tt.WantErr) {
						t.Fatalf("expected error '%v' but get error '%v'", tt.WantErr, err)
					}
				}

				if tt.IsWantMatch {
					if !isMatch {
						t.Fatalf("want password is match but not match")
					}
				} else {
					if isMatch {
						t.Fatalf("want password not match but is match")
					}
				}
			}
		})
	}
}
