package security_test

import (
	"bytes"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/pkg/security"
)

func TestSHA256Hash(t *testing.T) {
	data := []byte("random_bytes")

	hash, err := security.SHA256Hash(data)
	if err != nil {
		t.Fatal(err)
	}

	otherHash, err := security.SHA256Hash(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(hash, otherHash) {
		t.Error("hash mismatch")
	}
}
