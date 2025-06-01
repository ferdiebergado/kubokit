package security

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GenerateRandomBytes(length uint32) ([]byte, error) {
	key := make([]byte, length)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func GenerateRandomBytesEncoded(length uint32) (string, error) {
	key, err := GenerateRandomBytes(length)

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(key), nil
}

func CheckUint(i int) error {
	if i > int(^uint32(0)) {
		return fmt.Errorf("integer %d exceeds uint32", i)
	}
	return nil
}
