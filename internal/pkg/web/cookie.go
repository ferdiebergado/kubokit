package web

import (
	"errors"
	"net/http"
	"slices"
)

func FindCookie(cookies []*http.Cookie, name string) (*http.Cookie, error) {
	index := slices.IndexFunc(cookies, func(c *http.Cookie) bool {
		return c.Name == name
	})

	if index < 0 {
		return nil, errors.New("cookie not set")
	}

	foundCookie := cookies[index]
	cookie := &http.Cookie{
		Name:     foundCookie.Name,
		Value:    foundCookie.Value,
		Path:     foundCookie.Path,
		SameSite: foundCookie.SameSite,
		MaxAge:   foundCookie.MaxAge,
		HttpOnly: foundCookie.HttpOnly,
		Secure:   foundCookie.Secure,
	}
	return cookie, nil
}
