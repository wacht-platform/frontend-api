package deployment

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler"
)

func GetDeployment(c *fiber.Ctx) error {
	deployment := handler.GetDeployment(c)
	deployment.KepPair = nil

	return handler.SendSuccess(c, deployment)
}

func GetMetadata(c *fiber.Ctx) error {
	deployment := handler.GetDeployment(c)

	return handler.SendSuccess(c, deployment.UISettings)
}

func GetJwk(c *fiber.Ctx) error {
	deployment := handler.GetDeployment(c)

	return handler.SendSuccess(c, deployment.KepPair)
}
