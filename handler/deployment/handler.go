package deployment

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"gorm.io/gorm"
)

func GetDeployment(c fiber.Ctx) error {
	deployment := handler.GetDeployment(c)
	deployment.KepPair = nil

	return handler.SendSuccess(c, deployment)
}

func GetMetadata(c fiber.Ctx) error {
	deployment := handler.GetDeployment(c)

	return handler.SendSuccess(c, deployment.UISettings)
}

func GetJwk(c fiber.Ctx) error {
	deployment := handler.GetDeployment(c)

	return handler.SendSuccess(c, deployment.KepPair)
}

func GetJwks(c fiber.Ctx) error {
	deployment := handler.GetDeployment(c)
	if deployment.KepPair == nil {
		return handler.SendInternalServerError(c, nil, "Deployment key pair not found")
	}

	key, err := jwk.ParseKey([]byte(deployment.KepPair.PublicKey), jwk.WithPEM(true))
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to parse deployment public key")
	}

	if err := key.Set(jwk.KeyIDKey, strconv.FormatUint(deployment.KepPair.ID, 10)); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to assign JWK key id")
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to assign JWK key usage")
	}

	var crv jwa.EllipticCurveAlgorithm
	if err := key.Get(jwk.ECDSACrvKey, &crv); err == nil {
		switch crv {
		case jwa.P256():
			if err := key.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
				return handler.SendInternalServerError(c, err, "Failed to assign JWK algorithm")
			}
		case jwa.P384():
			if err := key.Set(jwk.AlgorithmKey, jwa.ES384()); err != nil {
				return handler.SendInternalServerError(c, err, "Failed to assign JWK algorithm")
			}
		case jwa.P521():
			if err := key.Set(jwk.AlgorithmKey, jwa.ES512()); err != nil {
				return handler.SendInternalServerError(c, err, "Failed to assign JWK algorithm")
			}
		}
	}

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to build JWKS")
	}

	return c.JSON(set)
}

func ValidateInvitation(c fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return handler.SendBadRequest(c, nil, "Token is required")
	}

	deployment := handler.GetDeployment(c)

	var invitation model.DeploymentInvitation
	err := database.Connection.
		Where("token = ? AND deployment_id = ? AND expiry > ?", token, deployment.ID, time.Now()).
		First(&invitation).Error

	if err == gorm.ErrRecordNotFound {
		response := ValidateInvitationResponse{
			Valid:     false,
			Message:   "Invalid or expired invitation",
			ErrorCode: handler.ErrCodeInvalidInvitationToken,
		}
		return handler.SendSuccess(c, response)
	} else if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to validate invitation")
	}

	response := ValidateInvitationResponse{
		Valid:     true,
		FirstName: invitation.FirstName,
		LastName:  invitation.LastName,
		Email:     invitation.EmailAddress,
	}
	return handler.SendSuccess(c, response)
}
