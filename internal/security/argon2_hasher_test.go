package security_test

import (
	"strings"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/security"
)

func TestArgon2Hasher_Hash(t *testing.T) {
	t.Parallel()
	opts := &config.Argon2Options{
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
	wantLen := 6
	gotLen := len(parts)
	if gotLen != wantLen {
		t.Errorf("len(parts) = %d, want: %d", gotLen, wantLen)
	}

	wantHasher := "argon2id"
	gotHasher := parts[1]
	if gotHasher != wantHasher {
		t.Errorf("parts[1] = %s, want: %s", gotHasher, wantHasher)
	}
}

func TestArgon2Hasher_Verify(t *testing.T) {
	t.Parallel()
	opts := &config.Argon2Options{
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
	matches, err := hasher.Verify(plain, hashed)
	if err != nil {
		t.Fatal(err)
	}
	if !matches {
		t.Errorf("hasher.Verify() = %v, want: %v", matches, true)
	}

	matches, err = hasher.Verify("garlic", hashed)
	if err != nil {
		t.Fatal(err)
	}

	if matches {
		t.Errorf("hasher.Verify() = %v, want: %v", matches, false)
	}
}
