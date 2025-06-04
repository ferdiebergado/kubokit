package stub

import (
	"errors"
	"time"
)

type Signer struct {
	SignFunc func(subject string, audience []string, duration time.Duration) (string, error)
}

func (s *Signer) Sign(subject string, audience []string, duration time.Duration) (string, error) {
	if s.SignFunc == nil {
		return "", errors.New("Sign not implemented by stub")
	}
	return s.SignFunc(subject, audience, duration)
}

func (s *Signer) Verify(tokenString string) (string, error) {
	panic("not implemented") // TODO: Implement
}
