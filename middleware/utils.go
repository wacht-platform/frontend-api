package middleware

import (
	"net"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler"
)

func checkIPAllowlist(c *fiber.Ctx, clientIP string, whitelistedIPs []string) error {
	if len(whitelistedIPs) == 0 {
		return nil
	}

	allowed := false
	for _, ip := range whitelistedIPs {
		if ip == clientIP {
			allowed = true
			break
		}
		_, ipNet, err := net.ParseCIDR(ip)
		if err == nil && ipNet.Contains(net.ParseIP(clientIP)) {
			allowed = true
			break
		}
	}
	if !allowed {
		return handler.SendForbidden(c, nil, "Access denied: IP address not allowed")
	}
	return nil
}
