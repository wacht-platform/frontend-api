package middleware

import (
	"net"

	"github.com/wacht-platform/frontend-api/handler"
)

func checkIPAllowlist(clientIP string, whitelistedIPs []string) error {
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
		return handler.ErrIPNotAllowed
	}
	return nil
}
