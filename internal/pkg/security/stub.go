package security

import "net/http"

type StubHardenedCookieBaker struct {
	BakeFunc func(string) *http.Cookie
}

func (s *StubHardenedCookieBaker) Bake(val string) *http.Cookie {
	if s.BakeFunc == nil {
		panic("Bake not implemented by stub")
	}
	return s.BakeFunc(val)
}
