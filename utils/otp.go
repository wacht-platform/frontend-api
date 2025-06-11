package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func GenerateOTP() (string, error) {
	otp := make([]byte, 6)

	for i := 0; i < 6; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("failed to generate OTP digit: %v", err)
		}
		otp[i] = byte('0' + n.Int64())
	}

	return string(otp), nil
}
