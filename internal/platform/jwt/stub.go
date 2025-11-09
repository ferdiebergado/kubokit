package jwt

import (
	"errors"
	"time"
)

type StubSigner struct {
	SignFunc   func(subject string, audience []string, duration time.Duration) (string, error)
	VerifyFunc func(tokenString string) (*Claims, error)
}

func (s *StubSigner) Sign(subject string, audience []string, duration time.Duration) (string, error) {
	if s.SignFunc == nil {
		return "", errors.New("Sign() not implemented by stub")
	}

	return s.SignFunc(subject, audience, duration)
}

func (s *StubSigner) Verify(tokenString string) (*Claims, error) {
	if s.VerifyFunc == nil {
		return nil, errors.New("Verify() not implemented by stub")
	}

	return s.VerifyFunc(tokenString)
}
