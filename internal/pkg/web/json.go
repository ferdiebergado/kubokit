package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"
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

func DecodeJSONResponse(t *testing.T, res *http.Response) map[string]any {
	t.Helper()

	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode json response: %v", err)
	}

	return body
}
