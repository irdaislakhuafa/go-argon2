package main

import (
	"fmt"

	"github.com/irdaislakhuafa/go-argon2/hash"
)

const (
	password = "this is password"
)

func main() {
	encodedHash, err := hash.HashArgon2([]byte(password))
	if err != nil {
		panic(err)
	}

	fmt.Println("argon2 hash:", encodedHash)

	isEquals, err := hash.CompareArgon2(password, encodedHash)
	if err != nil {
		panic(err)
	}
	fmt.Println("is equals:", isEquals)
}
