package web

import "net/http"

// Baker defines methods for baking and verifying HTTP cookies.
type Baker interface {
	Bake() (*http.Cookie, error)
	Check(*http.Cookie) error
}
