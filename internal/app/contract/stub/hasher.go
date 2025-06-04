package stub

import "errors"

type Hasher struct {
	HashFunc func(plain string) (string, error)
}

func (h *Hasher) Hash(plain string) (string, error) {
	if h.HashFunc == nil {
		return "", errors.New("Hash is not implemented by stub")
	}
	return h.HashFunc(plain)
}

func (h *Hasher) Verify(plain, hash string) (bool, error) {
	panic("not implemented") // TODO: Implement
}
