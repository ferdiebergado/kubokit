package security

import (
	"fmt"
	"time"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

type GolangJWTSigner struct {
	method jwt.SigningMethod
	key    string
	jtiLen uint32
	issuer string
}

func NewGolangJWTSigner(key string, cfg *config.JWT) *GolangJWTSigner {
	return &GolangJWTSigner{
		method: jwt.SigningMethodHS256,
		key:    key,
		jtiLen: cfg.JTILength,
		issuer: cfg.Issuer,
	}
}

func (s *GolangJWTSigner) Sign(subject string, audience []string, duration time.Duration) (string, error) {
	id, err := GenerateRandomBytesEncoded(s.jtiLen)
	if err != nil {
		return "", err
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
		return "", err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return "", fmt.Errorf("token claims is not a RegisteredClaims: %T", token.Claims)
	}

	return claims.Subject, nil
}
