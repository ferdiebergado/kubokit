package jwt_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
)

func TestSignAndVerify_Success(t *testing.T) {
	const (
		key      = "123"
		userID   = "1"
		issuer   = "me"
		audience = "you"
		idLen    = 8
		jti      = "abc"
	)

	randomizer := security.RandomizeFunc(func(length uint32) (string, error) {
		return jti, nil
	})

	signer := jwt.NewGolangJWTSigner(key, idLen, issuer, audience, randomizer)

	claims := map[string]any{
		"sub": userID,
	}

	ttl := 5 * time.Minute
	now := time.Now()
	exp := time.Now().Add(ttl)
	token, err := signer.Sign(claims, ttl)
	if err != nil {
		t.Fatal(err)
	}

	if token == "" {
		t.Errorf("token = %q, want: non-empty", token)
	}

	res, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("Verify returned an error: %v", err)
	}

	wantClaims := map[string]any{
		"jti": jti,
		"sub": userID,
		"iss": issuer,
		"aud": audience,
		"exp": float64(exp.Unix()),
		"iat": float64(now.Unix()),
		"nbf": float64(now.Unix()),
	}

	if !reflect.DeepEqual(res, wantClaims) {
		t.Errorf("signer.Verify(token) = %v, want: %v", res, wantClaims)
	}
}
