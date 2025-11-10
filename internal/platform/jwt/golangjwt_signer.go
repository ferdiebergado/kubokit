package jwt

import (
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

type Randomizer interface {
	Randomize(length uint32) (string, error)
}

type golangJWTSigner struct {
	method     jwt.SigningMethod
	key        []byte
	idLen      uint32
	issuer     string
	audience   string
	randomizer Randomizer
}

// NewGolangJWTSigner returns a new GolangJWTSigner instance with the given options.
func NewGolangJWTSigner(key string, idLen uint32, issuer, audience string, randomizer Randomizer) auth.Signer {
	return &golangJWTSigner{
		method:     jwt.SigningMethodHS256,
		key:        []byte(key),
		idLen:      idLen,
		issuer:     issuer,
		audience:   audience,
		randomizer: randomizer,
	}
}

var _ auth.Signer = (*golangJWTSigner)(nil)

// Sign creates a signed JWT token string from the provided claims.
func (g *golangJWTSigner) Sign(claims map[string]any, ttl time.Duration) (string, error) {
	now := time.Now()

	tokenClaims := jwt.MapClaims{}
	maps.Copy(tokenClaims, claims)

	jti, err := g.randomizer.Randomize(g.idLen)
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	tokenClaims["jti"] = jti
	tokenClaims["iss"] = g.issuer
	tokenClaims["aud"] = g.audience
	tokenClaims["exp"] = now.Add(ttl).Unix()
	tokenClaims["iat"] = now.Unix()
	tokenClaims["nbf"] = now.Unix()

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
	}, jwt.WithValidMethods([]string{g.method.Alg()}), jwt.WithIssuer(g.issuer), jwt.WithAudience(g.audience))

	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		result := make(map[string]any, len(claims))
		maps.Copy(result, claims)
		return result, nil
	}

	return nil, errors.New("invalid token")
}
