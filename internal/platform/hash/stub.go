package hash

import "errors"

type StubHasher struct {
	HashFunc func(plain string) (string, error)
}

func (h *StubHasher) Hash(plain string) (string, error) {
	if h.HashFunc == nil {
		return "", errors.New("Hash is not implemented by stub")
	}
	return h.HashFunc(plain)
}

func (h *StubHasher) Verify(plain, hash string) (bool, error) {
	panic("not implemented") // TODO: Implement
}
