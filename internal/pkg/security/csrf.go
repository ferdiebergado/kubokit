package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

var _ web.Baker = &CSRFCookieBaker{}

type CSRFCookieBaker struct {
	name       string
	length     uint32
	expiration time.Duration
	pepper     string
}

func (c *CSRFCookieBaker) Bake() (*http.Cookie, error) {
	token, err := GenerateRandomBytesURLEncoded(c.length)
	if err != nil {
		return nil, err
	}

	h := hmac.New(sha256.New, []byte(c.pepper))
	h.Write([]byte(token))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	signedToken := token + ":" + signature

	csrfCookie := NewSecureCookie(c.name, signedToken, c.expiration)
	csrfCookie.HttpOnly = false

	return csrfCookie, nil
}

// Check verifies the signature of the provided CSRF token.
func (c *CSRFCookieBaker) Check(csrfCookie *http.Cookie) error {
	parts := strings.SplitN(csrfCookie.Value, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("split signed token: %w", errors.New("invalid token"))
	}
	token, sig := parts[0], parts[1]

	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("base64 decode signature: %w", err)
	}

	h := hmac.New(sha256.New, []byte(c.pepper))
	h.Write([]byte(token))
	expectedSig := h.Sum(nil)

	if ok := hmac.Equal(sigBytes, expectedSig); !ok {
		return fmt.Errorf("hmac compare: %w", errors.New("mac mismatch"))
	}
	return nil
}

// NewCSRFCookieBaker creates and returns a new instance of CSRFCookieBaker configured
// with the provided CSRF configuration and security key.
func NewCSRFCookieBaker(cfg *config.CSRF, securityKey string) *CSRFCookieBaker {
	return &CSRFCookieBaker{
		name:       cfg.CookieName,
		length:     cfg.TokenLength,
		expiration: cfg.CookieMaxAge.Duration,
		pepper:     securityKey,
	}
}
