package security

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ferdiebergado/slim/internal/config"
	"golang.org/x/crypto/argon2"
)

type Argon2Hasher struct {
	memory     uint32
	iterations uint32
	threads    uint8
	saltLen    uint32
	keyLen     uint32
	pepper     string
}

func NewArgon2Hasher(cfg *config.Argon2Options, pepper string) *Argon2Hasher {
	return &Argon2Hasher{
		memory:     cfg.Memory,
		iterations: cfg.Iterations,
		threads:    cfg.Threads,
		saltLen:    cfg.SaltLength,
		keyLen:     cfg.KeyLength,
		pepper:     pepper,
	}
}

// Hash implements Hasher.
func (h *Argon2Hasher) Hash(plain string) (string, error) {
	// Generate a random salt
	salt, err := GenerateRandomBytes(h.saltLen)
	if err != nil {
		return "", fmt.Errorf("generate salt with length %d: %w", h.saltLen, err)
	}

	// Hash the password
	hash := argon2.IDKey([]byte(plain+h.pepper), salt, h.iterations, h.memory, h.threads, h.keyLen)

	// Encode the salt and hash for storage
	saltBase64 := base64.RawStdEncoding.EncodeToString(salt)
	hashBase64 := base64.RawStdEncoding.EncodeToString(hash)

	// Return the formatted password hash
	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		h.memory, h.iterations, h.threads, saltBase64, hashBase64)

	return encoded, nil
}

// Verify implements Hasher.
func (h *Argon2Hasher) Verify(plain string, hashed string) (bool, error) {
	parts := strings.Split(hashed, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid hash format")
	}

	var memory, time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("base64 decode salt: %w", err)
	}

	actualHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("base64 decode hash: %w", err)
	}

	hashLen := len(actualHash)
	if hashLen > int(^uint32(0)) {
		return false, fmt.Errorf("hash length %d exceeds uint32:", hashLen)
	}

	computedHash := argon2.IDKey([]byte(plain+h.pepper), salt, time, memory, threads, uint32(hashLen))
	if subtle.ConstantTimeCompare(computedHash, actualHash) == 1 {
		return true, nil
	}
	return false, nil
}
