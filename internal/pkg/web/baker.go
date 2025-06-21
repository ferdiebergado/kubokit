package web

import "net/http"

type Baker interface {
	Bake() (*http.Cookie, error)
}
