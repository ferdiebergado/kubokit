package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

const (
	HeaderContentType = "Content-Type"
	MimeJSON          = "application/json"
)

// SendJSON sends a JSON response with the given status code and data.
func SendJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set(HeaderContentType, MimeJSON)
	w.WriteHeader(statusCode)

	if data == nil {
		return
	}

	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Error encoding JSON response", "reason", err)
	}
}
