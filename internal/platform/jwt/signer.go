package jwt

import (
	"time"
)

type Signer interface {
	Sign(subject string, audience []string, duration time.Duration) (string, error)
	Verify(tokenString string) (string, error)
}
