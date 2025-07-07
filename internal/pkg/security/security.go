package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func GenerateRandomBytes(length uint32) ([]byte, error) {
	key := make([]byte, length)

	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}

	return key, nil
}

func GenerateRandomBytesStdEncoded(length uint32) (string, error) {
	key, err := GenerateRandomBytes(length)

	if err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	return base64.StdEncoding.EncodeToString(key), nil
}

func GenerateRandomBytesURLEncoded(length uint32) (string, error) {
	key, err := GenerateRandomBytes(length)

	if err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	return base64.URLEncoding.EncodeToString(key), nil
}

func CheckUint(i int) error {
	if i > int(^uint32(0)) {
		return fmt.Errorf("integer %d exceeds uint32", i)
	}
	return nil
}

// Constant time comparison
func ConstantTimeCompareStr(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := range len(a) {
		result |= int(a[i] ^ b[i])
	}
	return result == 0
}

func SHA256Hash(data []byte) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("hasher write data: %w", err)
	}

	hashBytes := h.Sum(nil)
	return hashBytes, nil
}
