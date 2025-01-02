package deployment

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler"
)

func GetDeployment(c *fiber.Ctx) error {
	deployment := handler.GetDeployment(c)

	return c.JSON(deployment)
}
