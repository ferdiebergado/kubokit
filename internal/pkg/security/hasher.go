package security

type ShortHasher interface {
	Hash(string) ([]byte, error)
}

type SHA256Hasher struct {
	securityKey string
}

func (h *SHA256Hasher) Hash(s string) ([]byte, error) {
	return SHA256Hash(s, h.securityKey)
}

func NewSHA256Hasher(key string) *SHA256Hasher {
	return &SHA256Hasher{
		securityKey: key,
	}
}
