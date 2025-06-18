package security

import (
	"crypto/rand"
	"fmt"
)

type RandomizerFunc func(length uint32) ([]byte, error)

func (r RandomizerFunc) GenerateRandomBytes(length uint32) ([]byte, error) {
	return r(length)
}

var StdlibRandomizer = RandomizerFunc(func(length uint32) ([]byte, error) {
	key := make([]byte, length)

	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}

	return key, nil
})
