package middleware_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func TestDecodePayload(t *testing.T) {
	t.Parallel()

	const header = "X-Handler-Called"

	type person struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}

	tests := []struct {
		name     string
		code     int
		payload  []byte
		bodySize int64
		header   string
	}{
		{"Valid payload", http.StatusOK, []byte(`{"name":"juan","age":47}`), 32, "true"},
		{"Payload too large", http.StatusRequestEntityTooLarge, []byte(`{"name": "agnis", "age": 13}`), 4, ""},
		{"Unknown field", http.StatusUnprocessableEntity, []byte(`{"name": "yaye", "age": 12, "is_smart": true}`), 64, ""},
		{"Extra payload", http.StatusBadRequest, []byte(`{"name": "bibi buy", "age": 2}{"name": "aremondeng", "age": 6}`), 64, ""},
		{"Incorrect data type", http.StatusBadRequest, []byte(`{"name": "agnis", "age": "13"}`), 64, ""},
		{"Malformed payload", http.StatusBadRequest, []byte(`{"name"`), 64, ""},
		{"Array passed to string", http.StatusBadRequest, []byte(`{"name": ["agnis", "yaye"], "age": "13"}`), 64, ""},
		{"Array within a string", http.StatusBadRequest, []byte(`{"name": "["agnis", "yaye"]", "age": "13"}`), 64, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				params, err := web.ParamsFromContext[person](r.Context())
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}

				w.Header().Set(header, "true")
				w.WriteHeader(http.StatusOK)
				if err := json.NewEncoder(w).Encode(&params); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			})

			body := bytes.NewBuffer(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/", body)
			rec := httptest.NewRecorder()
			mw := middleware.DecodePayload[person](tt.bodySize)(handler)
			mw.ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, tt.code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			gotHeader, wantHeader := rec.Header().Get(header), tt.header
			if gotHeader != wantHeader {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", header, gotHeader, wantHeader)
			}

			gotBody := strings.TrimSuffix(rec.Body.String(), "\n")
			wantBody := string(tt.payload)
			if tt.header == "true" && gotBody != wantBody {
				t.Errorf("rec.Body.String() = %q, want: %q", gotBody, wantBody)
			}
		})
	}
}
