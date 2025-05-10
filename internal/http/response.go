package http

import (
	"log/slog"
	"net/http"

	"github.com/ferdiebergado/gopherkit/http/response"
)

type OKResponse[T any] struct {
	Message string `json:"message,omitempty"`
	Data    T      `json:"data,omitempty"`
}

type ErrorResponse struct {
	Message string            `json:"message,omitempty"`
	Errors  map[string]string `json:"errors,omitempty"`
}

func OK[T any](w http.ResponseWriter, status int, msg *string, data *T) {
	payload := &OKResponse[*T]{}
	if msg != nil {
		payload.Message = *msg
	}

	if data != nil {
		payload.Data = data
	}

	response.JSON(w, status, payload)
}

func Fail(w http.ResponseWriter, status int, reason error, msg string) {
	slog.Error("request failed", "reason", reason)
	payload := &ErrorResponse{
		Message: msg,
	}
	response.JSON(w, status, payload)
}
