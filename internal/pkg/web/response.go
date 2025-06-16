package web

import (
	"log/slog"
	"net/http"
)

// OKResponse represents the structure of a JSON-encoded success response.
type OKResponse[T any] struct {
	Message string `json:"message,omitempty"`
	Data    T      `json:"data,omitempty"`
}

// RespondJSON sends a JSON response with the specified status code, client message and data.
func RespondJSON[T any](w http.ResponseWriter, statusCode int, clientMsg *string, data *T) {
	payload := &OKResponse[T]{}

	if clientMsg != nil {
		payload.Message = *clientMsg
	}

	if data != nil {
		payload.Data = *data
	}

	SendJSON(w, statusCode, payload)
}

// RespondOK sends a 200 OK JSON response.
func RespondOK[T any](w http.ResponseWriter, clientMsg *string, data T) {
	RespondJSON(w, http.StatusOK, clientMsg, &data)
}

// RespondCreated sends a 201 OK JSON response.
func RespondCreated[T any](w http.ResponseWriter, clientMsg *string, data T) {
	RespondJSON(w, http.StatusCreated, clientMsg, &data)
}

// ErrorResponse represents the structure of a JSON-encoded error response.
type ErrorResponse struct {
	Message string            `json:"message"`
	Details map[string]string `json:"errors,omitempty"`
}

// RespondError sends an error JSON response with the given status code and error details.
func RespondError(w http.ResponseWriter, status int, err error, clientMsg string, details map[string]string) {
	slog.Error("request failed", "reason", err)
	payload := &ErrorResponse{
		Message: clientMsg,
		Details: details,
	}

	SendJSON(w, status, payload)
}

// RespondBadRequest sends a 400 Bad Request error.
func RespondBadRequest(w http.ResponseWriter, err error, clientMsg string, details map[string]string) {
	RespondError(w, http.StatusBadRequest, err, clientMsg, details)
}

// RespondUnauthorized sends a 401 Unauthorized error.
func RespondUnauthorized(w http.ResponseWriter, err error, clientMsg string, details map[string]string) {
	RespondError(w, http.StatusUnauthorized, err, clientMsg, details)
}

// RespondInternalServerError sends a 500 Internal Server error.
func RespondInternalServerError(w http.ResponseWriter, err error) {
	RespondError(w, http.StatusInternalServerError, err, "an unexpected error occurred", nil)
}

// RespondUnprocessableEntity sends a 422 Unprocessable Entity error.
func RespondUnprocessableEntity(w http.ResponseWriter, err error, clientMsg string, details map[string]string) {
	RespondError(w, http.StatusUnprocessableEntity, err, clientMsg, details)
}

// RespondUnsupportedMediaType sends a 415 Unsupported Media Type error.
func RespondUnsupportedMediaType(w http.ResponseWriter, err error, clientMsg string, details map[string]string) {
	RespondError(w, http.StatusUnsupportedMediaType, err, clientMsg, details)
}

// RespondRequestEntityTooLarge sends a 413 Request Entity Too Large error.
func RespondRequestEntityTooLarge(w http.ResponseWriter, err error, clientMsg string, details map[string]string) {
	RespondError(w, http.StatusRequestEntityTooLarge, err, clientMsg, details)
}

// RespondRequestTimeout sends a 408 Request Timeout error.
func RespondRequestTimeout(w http.ResponseWriter, err error, clientMsg string, details map[string]string) {
	RespondError(w, http.StatusRequestTimeout, err, clientMsg, details)
}

// RespondConflict sends a 409 Conflict error.
func RespondConflict(w http.ResponseWriter, err error, clientMsg string, details map[string]string) {
	RespondError(w, http.StatusConflict, err, clientMsg, details)
}

// RespondForbidden sends a 403 Forbidden error.
func RespondForbidden(w http.ResponseWriter, err error, clientMsg string, details map[string]string) {
	RespondError(w, http.StatusForbidden, err, clientMsg, details)
}
