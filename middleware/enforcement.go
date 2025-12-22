package middleware

import (
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
)

func EnforceB2BSettings(c *fiber.Ctx) error {
	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if session.ActiveSignin == nil {
		return c.Next()
	}

	clientIP := c.IP()

	if d.B2BSettings.IpAllowlistPerOrgEnabled && session.ActiveSignin.ActiveOrganizationMembershipID != nil {
		if session.ActiveSignin.ActiveOrganizationMembership != nil {
			org := session.ActiveSignin.ActiveOrganizationMembership.Organization
			if org != nil && org.EnableIPRestriction && len(org.WhitelistedIPs) > 0 {
				if err := checkIPAllowlist(c, clientIP, org.WhitelistedIPs); err != nil {
					return err
				}
			}
		}
	}

	if d.B2BSettings.IpAllowlistPerWorkspaceEnabled && session.ActiveSignin.ActiveWorkspaceMembershipID != nil {
		if session.ActiveSignin.ActiveWorkspaceMembership != nil {
			workspace := session.ActiveSignin.ActiveWorkspaceMembership.Workspace
			if workspace != nil && workspace.EnableIPRestriction && len(workspace.WhitelistedIPs) > 0 {
				if err := checkIPAllowlist(c, clientIP, workspace.WhitelistedIPs); err != nil {
					return err
				}
			}
		}
	}

	shouldEnforceMFA := false

	if d.B2BSettings.EnforceMfaPerOrgEnabled && session.ActiveSignin.ActiveOrganizationMembershipID != nil {
		shouldEnforceMFA = true
	}

	if d.B2BSettings.EnforceMfaPerWorkspaceEnabled && session.ActiveSignin.ActiveWorkspaceMembershipID != nil {
		shouldEnforceMFA = true
	}

	if session.ActiveSignin.User != nil && session.ActiveSignin.User.SecondFactorPolicy == "enforced" {
		shouldEnforceMFA = true
	}

	if shouldEnforceMFA {
		var user model.User
		if err := database.Connection.Preload("UserAuthenticator").First(&user, *session.ActiveSignin.UserID).Error; err == nil {

			if user.UserAuthenticator != nil || user.BackupCodesGenerated {
				return c.Next()
			}

			path := c.Path()
			if strings.HasPrefix(path, "/auth/mfa") || strings.HasPrefix(path, "/auth/setup-mfa") {
				return c.Next()
			}

			return handler.SendForbidden(
				c,
				nil,
				"MFA is required for this organization/workspace",
				handler.ErrMfaRequired,
			)
		}
	}

	return c.Next()
}

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
		// Check CIDR
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
