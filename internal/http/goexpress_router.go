package http

import (
	"net/http"
	"strings"

	"github.com/ferdiebergado/goexpress"
	"github.com/ferdiebergado/kubokit/internal/contract"
)

var _ contract.Router = &GoexpressRouter{}

type GoexpressRouter struct {
	handler *goexpress.Router
}

func NewGoexpressRouter() *GoexpressRouter {
	return &GoexpressRouter{
		handler: goexpress.New(),
	}
}

func (r *GoexpressRouter) Delete(pattern string, handlerFunc http.HandlerFunc,
	middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Delete(pattern, handlerFunc, middlewares...)
}

func (r *GoexpressRouter) Get(pattern string, handlerFunc http.HandlerFunc,
	middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Get(pattern, handlerFunc, middlewares...)
}

func (r *GoexpressRouter) Options(pattern string, handlerFunc http.HandlerFunc,
	middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Options(pattern, handlerFunc, middlewares...)
}

func (r *GoexpressRouter) Patch(pattern string, handlerFunc http.HandlerFunc,
	middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Patch(pattern, handlerFunc, middlewares...)
}

func (r *GoexpressRouter) Post(pattern string, handlerFunc http.HandlerFunc,
	middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Post(pattern, handlerFunc, middlewares...)
}

func (r *GoexpressRouter) Put(pattern string, handlerFunc http.HandlerFunc,
	middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Put(pattern, handlerFunc, middlewares...)
}

func (r *GoexpressRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.handler.ServeHTTP(w, req)
}

func (r *GoexpressRouter) Use(middleware func(next http.Handler) http.Handler) {
	r.handler.Use(middleware)
}

func (r *GoexpressRouter) Group(prefix string, handlerFunc func(r contract.Router),
	middlewares ...func(next http.Handler) http.Handler) {
	gr := NewGoexpressRouter()
	handlerFunc(gr)

	const sep = "/"
	path := prefix
	if !strings.HasSuffix(path, sep) {
		path += sep
	}
	prefix = strings.TrimSuffix(prefix, sep)

	r.handler.Handle(path, http.StripPrefix(prefix, gr), middlewares...)
}
