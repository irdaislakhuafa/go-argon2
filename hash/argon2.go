package hash

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// default delimiter for argon2 hash format
	defaultDelimiter = "$"

	// standard length of values from argon2 hashed string with default delimiter
	standardLengthValues = 6

	/*
		NOTE: values with '$' as delimiter
			1: hash algorithm name
			2: argon2 (v)ersion
			3: (m)emory, i(t)erations, (p)arallelism used for hash
			4: salt with encoded base64
			5: hash with encoded base64
	*/
	standardHashFormat = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
)

type params struct {
	salt        []byte
	iterations  uint32
	memory      uint32
	parallelism uint8
	keyLen      uint32
}

func HashArgon2(password []byte) (string, error) {
	// prepare parameters
	p := params{
		salt:        make([]byte, 16),
		iterations:  3,
		memory:      (4 * 1024),
		parallelism: 1,
		keyLen:      32,
	}

	// generate salt with random number
	if _, err := rand.Read(p.salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(password, p.salt, p.iterations, p.memory, p.parallelism, p.keyLen)
	encodedHash, err := encodeHash(&p, hash)
	if err != nil {
		return "", err
	}

	return encodedHash, nil
}

func encodeHash(p *params, hash []byte) (string, error) {
	base64Salt := base64.RawStdEncoding.EncodeToString(p.salt)
	base64Hash := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash := fmt.Sprintf(standardHashFormat, argon2.Version, p.memory, p.iterations, p.parallelism, base64Salt, base64Hash)
	return encodedHash, nil
}
