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
		t.Errorf("\ngot: %d\nwant: %d\n", gotLen, wantLen)
	}

	wantHasher, gotHasher := "argon2id", parts[1]
	if gotHasher != wantHasher {
		t.Errorf("\ngot: %s\nwant: %s\n", gotHasher, wantHasher)
	}
}

func TestArgon2Hasher_Verify(t *testing.T) {
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
	matches, err := hasher.Verify(plain, hashed)
	if err != nil {
		t.Fatal(err)
	}
	if !matches {
		t.Errorf("\ngot: %v\nwant: %v\n", matches, true)
	}

	matches, err = hasher.Verify("garlic", hashed)
	if err != nil {
		t.Fatal(err)
	}

	if matches {
		t.Errorf("\ngot: %v\nwant: %v\n", matches, false)
	}
}
