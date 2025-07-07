package security_test

import (
	"bytes"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/pkg/security"
)

func TestSHA256Hasher(t *testing.T) {
	data := []byte("signature")

	hash, err := security.SHA256Hasher.Hash(data)
	if err != nil {
		t.Fatal(err)
	}

	otherHash, err := security.SHA256Hasher.Hash(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(hash, otherHash) {
		t.Error("hash mismatch")
	}
}
