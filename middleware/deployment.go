package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
)

func SetDeploymentMiddleware(c *fiber.Ctx) error {
	host := c.Hostname()

	path := c.Path()

	if strings.HasPrefix(path, "/.well") {
		return c.Next()
	}

	deployment := new(model.Deployment)
	err := database.Connection.Where("host = ?", host).
		Joins("OrgSettings").
		Joins("AuthSettings").
		Joins("KepPair").
		Preload("SocialConnections").
		First(&deployment).
		Error
	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"message": "Deployment not found",
		})
	}

	c.Locals("deployment", *deployment)

	return c.Next()
}
