package jwt

import (
	"time"
)

// Claims represents the JWT claims that are processed for authentication.
type Claims struct {
	UserID string
}

// Signer defines methods for signing and verifying JWT tokens.
type Signer interface {
	Sign(subject string, audience []string, duration time.Duration) (token string, err error)
	Verify(tokenString string) (*Claims, error)
}
