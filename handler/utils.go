package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/model"
)

func GetDeployment(c *fiber.Ctx) model.Deployment {
	deployment := c.Locals("deployment")

	return deployment.(model.Deployment)
}
