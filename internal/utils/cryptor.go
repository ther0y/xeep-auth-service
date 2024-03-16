package utils

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
)

func HashPassword(password string) (string, string) {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)

	saltString := hex.EncodeToString(salt)

	hashedPassword := pbkdf2.Key([]byte(password), salt, 1000, 64, sha512.New)
	hashedPasswordString := hex.EncodeToString(hashedPassword)

	return hashedPasswordString, saltString
}
