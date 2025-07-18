package web

import (
	"net/http"
	"strings"
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
