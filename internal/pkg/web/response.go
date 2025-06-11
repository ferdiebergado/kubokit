package web

import (
	"log/slog"
	"net/http"

	"github.com/ferdiebergado/gopherkit/http/response"
)

// OKResponse represents the structure of a JSON-encoded success response.
//
// It includes an optional message and optional data payload. The generic type
// parameter T allows OKResponse to carry arbitrary response data.
//
// The Data field is omitted from the response if it is nil.
type OKResponse[T any] struct {
	Message string `json:"message,omitempty"`
	Data    T      `json:"data,omitempty"`
}

// ErrorResponse represents the structure of a JSON-encoded error response.
//
// It includes a general error message and, optionally, a map of field-level
// validation errors. The Errors field is omitted from the response if empty.
type ErrorResponse struct {
	Message string            `json:"message"`
	Errors  map[string]string `json:"errors,omitempty"`
}

// OK writes a JSON-encoded success response to w with the provided HTTP status code.
//
// The response includes an optional human-readable message and an optional data payload.
// It is intended for successful API responses with a consistent structure.
//
// The type parameter T specifies the type of the response data.
//
// If msg is non-nil, its value is included in the response under the "message" field.
// If data is non-nil, it is included under the "data" field.
//
// Example usage:
//
//	msg := "User created successfully"
//	user := User{ID: 1, Name: "Alice"}
//	OK(w, http.StatusCreated, &msg, &user)
//
// The JSON response has the form:
//
//	{
//	  "message": "User created successfully",
//	  "data": {
//	    "id": 1,
//	    "name": "Alice"
//	  }
//	}
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

// Fail writes a JSON-encoded error response to w with the provided HTTP status code.
//
// The response includes a human-readable message and an optional map of
// field-specific validation errors. The reason is logged using slog at
// Error level with the key "reason". This function is intended to provide
// a consistent structure for API error responses.
//
// Example usage:
//
//	Fail(w, http.StatusBadRequest, err, "Invalid input.", map[string]string{
//		"email": "must be a valid email address",
//	})
//
// The JSON response has the form:
//
//	{
//	  "message": "Invalid input.",
//	  "errors": {
//	    "email": "must be a valid email address"
//	  }
//	}
func Fail(w http.ResponseWriter, status int, reason error, msg string, errs map[string]string) {
	slog.Error("request failed", "reason", reason)
	payload := &ErrorResponse{
		Message: msg,
		Errors:  errs,
	}
	response.JSON(w, status, payload)
}
