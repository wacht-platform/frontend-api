package utils

import (
	"errors"
	"strings"

	"github.com/matthewhartstonge/argon2"
	"golang.org/x/crypto/bcrypt"
)

var argon = argon2.DefaultConfig()

func HashPassword(password string) (string, error) {
	encoded, err := argon.HashEncoded([]byte(password))

	return string(encoded), err
}

func ComparePassword(hashedPassword, password string) (bool, error) {
	if strings.HasPrefix(hashedPassword, "$2a$") ||
		strings.HasPrefix(hashedPassword, "$2b$") ||
		strings.HasPrefix(hashedPassword, "$2y$") {
		err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err == nil {
			return true, nil
		}
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}

	if strings.HasPrefix(hashedPassword, "$argon2i$") ||
		strings.HasPrefix(hashedPassword, "$argon2d$") ||
		strings.HasPrefix(hashedPassword, "$argon2id$") {
		return argon2.VerifyEncoded(
			[]byte(password),
			[]byte(hashedPassword),
		)
	}

	return false, errors.New("unsupported password hash algorithm")
}
