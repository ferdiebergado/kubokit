package jwt_test

import (
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/config"
	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
)

func TestGolangJWTSigner_Sign(t *testing.T) {
	const key = "123"
	cfg := &config.JWT{
		JTILength:  8,
		Issuer:     "example.com",
		TTL:        timex.Duration{Duration: 15 * time.Minute},
		RefreshTTL: timex.Duration{Duration: 7 * 24 * time.Hour},
	}
	signer, err := jwt.NewGolangJWTSigner(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	userID := "user1"
	audience := []string{"example.com"}
	duration := cfg.TTL.Duration
	token, err := signer.Sign(userID, audience, duration)
	if err != nil {
		t.Fatal(err)
	}

	if token == "" {
		t.Errorf("signer.Sign(%q, %v, %v) = %q, want: not an empty string", userID, audience, duration, token)
	}
}

func TestGolangJWTSigner_Verify(t *testing.T) {
	const key = "123"
	cfg := &config.JWT{
		JTILength:  8,
		Issuer:     "example.com",
		TTL:        timex.Duration{Duration: 15 * time.Minute},
		RefreshTTL: timex.Duration{Duration: 7 * 24 * time.Hour},
	}
	signer, err := jwt.NewGolangJWTSigner(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	userID := "user1"
	audience := []string{"example.com"}
	duration := cfg.TTL.Duration
	token, err := signer.Sign(userID, audience, duration)
	if err != nil {
		t.Fatal(err)
	}

	gotUserID, err := signer.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	if gotUserID != userID {
		t.Errorf("signer.Verify(%q) = %q, want: %q", token, gotUserID, userID)
	}
}
