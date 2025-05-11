package contract

import (
	"net/http"
)

type Router interface {
	http.Handler

	Use(middleware func(next http.Handler) http.Handler)
	Get(pattern string, handlerFunc http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler)
	Post(pattern string, handlerFunc http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler)
	Put(pattern string, handlerFunc http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler)
	Patch(pattern string, handlerFunc http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler)
	Delete(pattern string, handlerFunc http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler)
	Options(pattern string, handlerFunc http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler)
	Group(pattern string, handlerFunc func(r Router), middlewares ...func(next http.Handler) http.Handler)
}
