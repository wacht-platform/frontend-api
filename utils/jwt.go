package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/wacht-platform/frontend-api/model"
	"gorm.io/gorm"
)

func SignNewJWT(
	sessionID uint64,
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

	return SignJWT(
		sessionID,
		uint64(rotatingToken.ID),
		iss,
		exp,
		keypair,
		tx,
	)
}

func SignJWT(
	sessionID uint64,
	rotatingTokenID uint64,
	iss string,
	exp time.Time,
	keypair model.DeploymentKeyPair,
	tx *gorm.DB,
) (string, error) {

	tok, err := jwt.NewBuilder().
		Issuer(fmt.Sprintf("https://%s", iss)).
		Expiration(exp).
		IssuedAt(time.Now()).
		NotBefore(time.Now()).
		Claim("sess", strconv.FormatUint(uint64(sessionID), 10)).
		Claim("rotating_token", strconv.FormatUint(uint64(rotatingTokenID), 10)).
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
		jwt.WithKey(jwa.ES256(), publicKey),
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
		jwt.WithKey(jwa.ES256(), publicKey),
		jwt.WithIssuer(fmt.Sprintf("https://%s", iss)),
	)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func GenerateOAuthStateToken(data map[string]interface{}, keypair model.DeploymentKeyPair) (string, error) {
	privateKeyBlock, _ := pem.Decode([]byte(keypair.PrivateKey))
	if privateKeyBlock == nil {
		return "", fmt.Errorf("failed to parse private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return "", err
	}

	token := jwt.New()
	for key, value := range data {
		if err := token.Set(key, value); err != nil {
			return "", err
		}
	}

	if err := token.Set(jwt.IssuedAtKey, time.Now()); err != nil {
		return "", err
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), privateKey))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

func ValidateOAuthStateToken(tokenString string, keypair model.DeploymentKeyPair) (map[string]interface{}, error) {
	publicKeyBlock, _ := pem.Decode([]byte(keypair.PublicKey))
	if publicKeyBlock == nil {
		return nil, fmt.Errorf("failed to parse public key PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse([]byte(tokenString), jwt.WithKey(jwa.ES256(), publicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid state token: %w", err)
	}

	var exp interface{}
	if token.Get("exp", &exp) == nil && exp != nil {
		expTime := time.Unix(int64(exp.(float64)), 0)
		if time.Now().After(expTime) {
			return nil, fmt.Errorf("state token expired")
		}
	}

	claims := make(map[string]interface{})

	var val interface{}
	if token.Get("user_id", &val) == nil && val != nil {
		claims["user_id"] = val
	}
	if token.Get("session_id", &val) == nil && val != nil {
		claims["session_id"] = val
	}
	if token.Get("provider", &val) == nil && val != nil {
		claims["provider"] = val
	}
	if token.Get("action", &val) == nil && val != nil {
		claims["action"] = val
	}
	if token.Get("exp", &val) == nil && val != nil {
		claims["exp"] = val
	}

	return claims, nil
}
