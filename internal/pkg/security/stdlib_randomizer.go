package security

import (
	"crypto/rand"
	"fmt"
)

type Randomizer func(length uint32) ([]byte, error)

func (r Randomizer) GenerateRandomBytes(length uint32) ([]byte, error) {
	return r(length)
}

var StdlibRandomizer = Randomizer(func(length uint32) ([]byte, error) {
	key := make([]byte, length)

	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}

	return key, nil
})
