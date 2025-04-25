package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/ilabs/wacht-fe/model"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gorm.io/gorm"
)

func SignJWT(
	sessionID uint,
	iss string,
	exp time.Time,
	keypair model.DeploymentKeyPair,
	tx *gorm.DB,
) (string, error) {
	rotatingToken := model.NewRotatingToken(
		sessionID,
		exp.Add(time.Hour*24*30),
	)

	err := tx.Create(rotatingToken).Error
	if err != nil {
		return "", err
	}

	tok, err := jwt.NewBuilder().
		Issuer(fmt.Sprintf("https://%s", iss)).
		Expiration(exp).
		IssuedAt(time.Now()).
		NotBefore(time.Now()).
		Claim("sess", sessionID).
		Claim("rotating_token", strconv.FormatUint(uint64(rotatingToken.ID), 10)).
		Build()
	if err != nil {
		return "", err
	}

	privateKeyBlock, _ := pem.Decode([]byte(keypair.PrivateKey))
	privateKey, err := x509.ParsePKCS8PrivateKey(
		privateKeyBlock.Bytes,
	)
	if err != nil {
		log.Fatal("Error parsing private key: ", err)
	}

	if err != nil {
		return "", err
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privateKey))

	return string(signed), err
}

func VerifyJWT(
	j string,
	keypair model.DeploymentKeyPair,
	iss string,
) (jwt.Token, error) {
	publicKeyBlock, _ := pem.Decode([]byte(keypair.PublicKey))
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(
		[]byte(j),
		jwt.WithKey(jwa.RS256(), publicKey),
		jwt.WithVerify(true),
		jwt.WithIssuer(fmt.Sprintf("https://%s", iss)),
	)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func ParseJWT(
	j string,
	keypair model.DeploymentKeyPair,
	iss string,
) (jwt.Token, error) {
	publicKeyBlock, _ := pem.Decode([]byte(keypair.PublicKey))
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseInsecure(
		[]byte(j),
		jwt.WithKey(jwa.RS256(), publicKey),
		jwt.WithIssuer(fmt.Sprintf("https://%s", iss)),
	)
	if err != nil {
		return nil, err
	}

	return token, nil
}
