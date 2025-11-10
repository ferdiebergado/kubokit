package jwt

import (
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/golang-jwt/jwt/v5"
)

type golangJWTSigner struct {
	method    jwt.SigningMethod
	key       []byte
	idLen     uint32
	issuer    string
	audience  string
	expiresIn time.Duration
}

// NewGolangJWTSigner returns a new GolangJWTSigner instance with the given options.
func NewGolangJWTSigner(key string, idLen uint32, issuer, audience string, expiresIn time.Duration) auth.Signer {
	return &golangJWTSigner{
		method:    jwt.SigningMethodHS256,
		key:       []byte(key),
		idLen:     idLen,
		issuer:    issuer,
		audience:  audience,
		expiresIn: expiresIn,
	}
}

var _ auth.Signer = (*golangJWTSigner)(nil)

// Sign creates a signed JWT token string from the provided claims.
func (g *golangJWTSigner) Sign(claims map[string]any) (string, error) {
	tokenClaims := make(jwt.MapClaims, len(claims))

	// Copy claims and add standard claims if missing (example: exp).
	maps.Copy(tokenClaims, claims)

	// Set token expiration if not present.
	if _, ok := tokenClaims["exp"]; !ok {
		tokenClaims["exp"] = time.Now().Add(g.expiresIn).Unix()
	}

	// Generate jti.
	jti, err := security.GenerateRandomBytes(g.idLen)
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	tokenClaims["jti"] = hex.EncodeToString(jti)
	tokenClaims["iss"] = g.issuer
	tokenClaims["aud"] = g.audience

	token := jwt.NewWithClaims(g.method, tokenClaims)
	signedToken, err := token.SignedString(g.key)
	if err != nil {
		return "", fmt.Errorf("create signed jwt: %w", err)
	}

	return signedToken, nil
}

// Verify parses and validates the JWT token string and returns claims if valid.
func (g *golangJWTSigner) Verify(tokenString string) (map[string]any, error) {
	token, err := jwt.Parse(tokenString, func(_ *jwt.Token) (any, error) {
		return g.key, nil
	}, jwt.WithValidMethods([]string{g.method.Alg()}))

	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		result := make(map[string]any, len(claims))
		for k, v := range claims {
			result[k] = v
		}
		return result, nil
	}

	return nil, errors.New("invalid token")
}
