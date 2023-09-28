package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

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
		return "", errors.Join(err)
	}

	hash := argon2.IDKey(password, p.salt, p.iterations, p.memory, p.parallelism, p.keyLen)
	encodedHash, err := encodeHash(&p, hash)
	if err != nil {
		return "", errors.Join(err)
	}

	return encodedHash, nil
}

func CompareArgon2(password, encodedHash string) (bool, error) {
	// extract all parameters include salt and key length from encoded password hash
	p, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// generate other password with same parameters and compare it with existsing hash
	if otherhash := argon2.IDKey([]byte(password), p.salt, p.iterations, p.memory, p.parallelism, p.keyLen); subtle.ConstantTimeCompare(hash, otherhash) != 1 {
		return false, ErrHashNotMatch
	}

	return true, nil
}

func encodeHash(p *params, hash []byte) (string, error) {
	base64Salt := base64.RawStdEncoding.EncodeToString(p.salt)
	base64Hash := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash := fmt.Sprintf(standardHashFormat, argon2.Version, p.memory, p.iterations, p.parallelism, base64Salt, base64Hash)
	return encodedHash, nil
}

func decodeHash(encodedHash string) (p *params, hash []byte, err error) {
	// split encoded argon2 hash with default delimiter
	values := strings.Split(encodedHash, defaultDelimiter)

	// compare length values with standart length
	if valueLength := len(values); valueLength != standardLengthValues {
		return nil, nil, errors.Join(ErrInvalidHashLength, errors.New(fmt.Sprintf("invalid length of encoded hash, expected %v but get %v", standardLengthValues, valueLength)))
	}

	// check incompatible argon2 version
	version := 0
	if _, err := fmt.Sscanf(values[2], "v=%d", &version); err != nil {
		return nil, nil, errors.Join(ErrArgon2Version, err)
	}

	if version != argon2.Version {
		return nil, nil, errors.Join(ErrIncompatibleArgon2Version, errors.New(fmt.Sprintf("current argon2 version is %d but encoded hash using version %d", argon2.Version, version)))
	}

	// mapping values for memory, iterations and parallelism
	p = &params{}
	if _, err := fmt.Sscanf(values[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism); err != nil {
		return nil, nil, errors.Join(ErrArgon2Format, err)
	}

	// decode base64 salt
	if p.salt, err = base64.RawStdEncoding.Strict().DecodeString(values[4]); err != nil {
		return nil, nil, errors.Join(ErrDecodeSalt, err)
	}

	// decode base64 hash
	if hash, err = base64.RawStdEncoding.Strict().DecodeString(values[5]); err != nil {
		return nil, nil, errors.Join(ErrDecodeHash, err)
	}
	p.keyLen = uint32(len(hash))

	return p, hash, nil
}
