package utils

import "github.com/matthewhartstonge/argon2"

var argon = argon2.DefaultConfig()

func HashPassword(password string) (string, error) {
	encoded, err := argon.HashEncoded([]byte(password))

	return string(encoded), err
}

func ComparePassword(hashedPassword, password string) (bool, error) {
	return argon2.VerifyEncoded(
		[]byte(password),
		[]byte(hashedPassword),
	)
}
