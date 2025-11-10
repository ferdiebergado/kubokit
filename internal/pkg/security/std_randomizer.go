package security

import "encoding/hex"

type RandomizeFunc func(length uint32) (string, error)

func (r RandomizeFunc) Randomize(length uint32) (string, error) {
	return r(length)
}

var STDRandomizer = RandomizeFunc(func(length uint32) (string, error) {
	b, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
})
