package security

type Randomizer interface {
	GenerateRandomBytes(length uint32) ([]byte, error)
}
