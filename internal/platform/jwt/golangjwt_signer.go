package jwt

import (
	"fmt"
	"time"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/golang-jwt/jwt/v5"
)

var _ Signer = &GolangJWTSigner{}

type GolangJWTSigner struct {
	method jwt.SigningMethod
	key    string
	jtiLen uint32
	issuer string
}

func (s *GolangJWTSigner) Sign(subject string, audience []string, duration time.Duration) (string, error) {
	id, err := security.GenerateRandomBytesStdEncoded(s.jtiLen)
	if err != nil {
		return "", fmt.Errorf("generate random bytes encoded with length %d: %w", s.jtiLen, err)
	}

	now := time.Now()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    s.issuer,
		Subject:   subject,
		ID:        id,
		Audience:  audience,
	}

	token := jwt.NewWithClaims(s.method, claims)
	return token.SignedString([]byte(s.key))
}

func (s *GolangJWTSigner) Verify(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(_ *jwt.Token) (any, error) {
		return []byte(s.key), nil
	}, jwt.WithValidMethods([]string{s.method.Alg()}))
	if err != nil {
		return "", fmt.Errorf("parse with claims: %w", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return "", fmt.Errorf("token claims is not a RegisteredClaims: %T", token.Claims)
	}

	return claims.Subject, nil
}

func NewGolangJWTSigner(cfg *config.JWT, key string) *GolangJWTSigner {
	return &GolangJWTSigner{
		method: jwt.SigningMethodHS256,
		key:    key,
		jtiLen: cfg.JTILength,
		issuer: cfg.Issuer,
	}
}
