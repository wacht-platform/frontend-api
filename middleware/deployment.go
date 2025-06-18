package middleware

import (
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/utils"
)

func SetDeploymentMiddleware(c *fiber.Ctx) error {
	host := c.Hostname()

	if net.ParseIP(host) != nil {
		return c.Status(404).JSON(fiber.Map{"message": "Deployment not found"})
	}

	path := c.Path()

	if strings.HasPrefix(path, "/.well") {
		return c.Next()
	}

	deployment, err := utils.GetDeploymentByHost(host)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"message": "Deployment not found"})
	}

	c.Locals("deployment", *deployment)

	return c.Next()
}
