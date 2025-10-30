package router

import (
	"net/http"

	"github.com/ferdiebergado/goexpress"
)

type GoexpressRouter struct {
	handler *goexpress.Router
}

func NewGoexpressRouter() *GoexpressRouter {
	return &GoexpressRouter{
		handler: goexpress.New(),
	}
}

var _ Router = &GoexpressRouter{}

func (r *GoexpressRouter) Delete(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Delete(pattern, handler, middlewares...)
}

func (r *GoexpressRouter) Get(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Get(pattern, handler, middlewares...)
}

func (r *GoexpressRouter) Options(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Options(pattern, handler, middlewares...)
}

func (r *GoexpressRouter) Patch(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Patch(pattern, handler, middlewares...)
}

func (r *GoexpressRouter) Post(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Post(pattern, handler, middlewares...)
}

func (r *GoexpressRouter) Put(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Put(pattern, handler, middlewares...)
}

func (r *GoexpressRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.handler.ServeHTTP(w, req)
}

func (r *GoexpressRouter) Use(middleware func(next http.Handler) http.Handler) {
	r.handler.Use(middleware)
}

func (r *GoexpressRouter) Group(prefix string, fn func(r Router), middlewares ...func(next http.Handler) http.Handler) {
	gr := NewGoexpressRouter()
	gr.handler.SetPrefix(prefix)
	gr.handler.SetMux(r.handler.Mux())
	gr.handler.SetMiddlewares(append(r.handler.Middlewares(), middlewares...))

	fn(gr)
}
