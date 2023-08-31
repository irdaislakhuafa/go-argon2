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
}
