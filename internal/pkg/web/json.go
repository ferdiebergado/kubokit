package web

import (
	"encoding/json"
	"fmt"
)

const (
	HeaderContentType = "Content-Type"
	MimeJSON          = "application/json"
)

func DecodeJSON[T any](inputBytes []byte, destination *T) error {
	if err := json.Unmarshal(inputBytes, destination); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}
