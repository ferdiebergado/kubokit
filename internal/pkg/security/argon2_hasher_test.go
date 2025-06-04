package security_test

import (
	"strings"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
)

func TestArgon2Hasher_Hash(t *testing.T) {
	t.Parallel()

	opts := &config.Argon2{
		Memory:     65535,
		Iterations: 3,
		Threads:    2,
		SaltLength: 16,
		KeyLength:  32,
	}
	pepper := "paminta"
	hasher := security.NewArgon2Hasher(opts, pepper)
	plain := "rice"
	hashed, err := hasher.Hash(plain)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(hashed, "$")
	wantLen, gotLen := 6, len(parts)
	if gotLen != wantLen {
		t.Errorf("len(%s) = %d\nwant: %d", parts, gotLen, wantLen)
	}

	wantHasher, gotHasher := "argon2id", parts[1]
	if gotHasher != wantHasher {
		t.Errorf("parts[1] = %s\nwant: %s", gotHasher, wantHasher)
	}
}

func TestArgon2Hasher_Verify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, plain, hashed string
		matches             bool
	}{
		{"Plain and hash matches", "rice", "rice", true},
		{"Plain and hash mismatches", "garlic", "rice", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := &config.Argon2{
				Memory:     65535,
				Iterations: 3,
				Threads:    2,
				SaltLength: 16,
				KeyLength:  32,
			}
			pepper := "paminta"
			hasher := security.NewArgon2Hasher(opts, pepper)
			hashed, err := hasher.Hash(tt.hashed)
			if err != nil {
				t.Fatal(err)
			}

			matches, err := hasher.Verify(tt.plain, hashed)
			if err != nil {
				t.Fatal(err)
			}
			if tt.matches != matches {
				t.Errorf("hasher.Verify(tt.plain, hashed) = %v\nwant: %v", matches, true)
			}
		})
	}
}
