package router

import (
	"net/http"

	"github.com/ferdiebergado/goexpress"
)

type goexpressRouter struct {
	handler *goexpress.Router
}

var _ Router = (*goexpressRouter)(nil)

func NewGoexpressRouter() Router {
	return &goexpressRouter{
		handler: goexpress.New(),
	}
}

func (r *goexpressRouter) Delete(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Delete(pattern, handler, middlewares...)
}

func (r *goexpressRouter) Get(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Get(pattern, handler, middlewares...)
}

func (r *goexpressRouter) Options(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Options(pattern, handler, middlewares...)
}

func (r *goexpressRouter) Patch(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Patch(pattern, handler, middlewares...)
}

func (r *goexpressRouter) Post(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Post(pattern, handler, middlewares...)
}

func (r *goexpressRouter) Put(pattern string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	r.handler.Put(pattern, handler, middlewares...)
}

func (r *goexpressRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.handler.ServeHTTP(w, req)
}

func (r *goexpressRouter) Use(middleware func(next http.Handler) http.Handler) {
	r.handler.Use(middleware)
}

func (r *goexpressRouter) Group(prefix string, fn func(r Router), middlewares ...func(next http.Handler) http.Handler) {
	gr := &goexpressRouter{
		handler: goexpress.New(),
	}
	gr.handler.SetPrefix(prefix)
	gr.handler.SetMux(r.handler.Mux())
	gr.handler.SetMiddlewares(append(r.handler.Middlewares(), middlewares...))

	fn(gr)
}
