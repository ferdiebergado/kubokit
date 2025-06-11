package router

import (
	"net/http"

	"github.com/ferdiebergado/goexpress"
)

var _ Router = &GoexpressRouter{}

type GoexpressRouter struct {
	handler *goexpress.Router
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

func (r *GoexpressRouter) Group(prefix string, fn func(r Router),
	middlewares ...func(next http.Handler) http.Handler) {

	gr := NewGoexpressRouter()
	gr.handler.SetPrefix(prefix)
	gr.handler.SetMux(r.handler.Mux())
	gr.handler.SetMiddlewares(append(r.handler.Middlewares(), middlewares...))

	fn(gr)
}

func NewGoexpressRouter() *GoexpressRouter {
	return &GoexpressRouter{
		handler: goexpress.New(),
	}
}
