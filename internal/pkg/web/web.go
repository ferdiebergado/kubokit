package web

import (
	"net/http"
	"strings"
	"testing"
)

func IsBrowser(r *http.Request) bool {
	userAgent := r.Header.Get("User-Agent")

	isBrowser := false

	browserKeywords := []string{
		"Mozilla",
		"Chrome",
		"Safari",
		"Firefox",
		"Edge",
		"Opera",
	}

	for _, keyword := range browserKeywords {
		if strings.Contains(userAgent, keyword) {
			isBrowser = true
			break
		}
	}

	return isBrowser
}

func AssertContentType(t *testing.T, res *http.Response) {
	t.Helper()

	gotContent := res.Header.Get(HeaderContentType)
	if !strings.HasPrefix(gotContent, MimeJSON) {
		t.Errorf("res.Header.Get(%q) = %q, want: %q", HeaderContentType, gotContent, MimeJSON)
	}
}
