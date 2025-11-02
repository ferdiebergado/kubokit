package jwt

import (
	"fmt"
	"time"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims represents JWT with custom claims.
type CustomClaims struct {
	jwt.RegisteredClaims
}

// golangJWTSigner implements the Signer interface using the golang-jwt library.
type golangJWTSigner struct {
	method jwt.SigningMethod
	key    string
	jtiLen uint32
	issuer string
}

var _ Signer = (*golangJWTSigner)(nil)

// NewGolangJWTSigner creates a new GolangJWTSigner with the provided JWT config and signing key.
func NewGolangJWTSigner(cfg *config.JWT, key string) Signer {
	return &golangJWTSigner{
		method: jwt.SigningMethodHS256,
		key:    key,
		jtiLen: cfg.JTILength,
		issuer: cfg.Issuer,
	}
}

// Sign generates a signed JWT token with the given subject, audience, and duration.
func (s *golangJWTSigner) Sign(sub string, audience []string, duration time.Duration) (string, error) {
	jti, err := security.GenerateRandomBytesURLEncoded(s.jtiLen)
	if err != nil {
		return "", fmt.Errorf("generate jti with length %d: %w", s.jtiLen, err)
	}

	claims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			Issuer:    s.issuer,
			Audience:  audience,
			Subject:   sub,
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(s.method, claims)
	signedToken, err := token.SignedString([]byte(s.key))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signedToken, nil
}

// Verify parses and validates a JWT token string and returns the associated Claims if valid.
func (s *golangJWTSigner) Verify(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(_ *jwt.Token) (any, error) {
		return []byte(s.key), nil
	}, jwt.WithValidMethods([]string{s.method.Alg()}))
	if err != nil {
		return nil, fmt.Errorf("parse with claims: %w", err)
	}

	customClaims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("unknown claims type: %T", token.Claims)
	}

	claims := &Claims{
		UserID: customClaims.Subject,
	}

	return claims, nil
}
