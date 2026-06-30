package router

import (
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler/captcha"
)

func setupCaptchaRoutes(app *fiber.App) {
	app.Post("/captcha/challenge", captcha.ProxyChallenge)
	app.Post("/captcha/redeem", captcha.ProxyRedeem)
}
