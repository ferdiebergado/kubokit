package contract

type Hasher interface {
	Hash(plain string) (string, error)
	Verify(plain, hashed string) (bool, error)
}
