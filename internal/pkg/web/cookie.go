package web

import (
	"net/http"
)

type Baker interface {
	Bake(val string) *http.Cookie
}
