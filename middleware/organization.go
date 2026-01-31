package middleware

import (
	"encoding/json"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
)

func SetOrganizationContext(c *fiber.Ctx) error {
	orgIDStr := c.Params("id")
	if orgIDStr == "" {
		return c.Next()
	}

	orgID, err := strconv.ParseUint(orgIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid organization ID")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership *model.OrganizationMembership
	var org *model.PublicOrganizationData

	if session.ActiveSignin.ActiveOrganizationMembershipID != nil &&
		session.ActiveSignin.ActiveOrganizationMembership != nil &&
		session.ActiveSignin.ActiveOrganizationMembership.OrganizationID == orgID {

		membership = session.ActiveSignin.ActiveOrganizationMembership
		org = session.ActiveSignin.ActiveOrganizationMembership.Organization
	} else {
		membership = new(model.OrganizationMembership)
		var membershipJSON string
		if err := database.Connection.Raw(`
			SELECT json_build_object(
				'id', om.id::text,
				'organization_id', om.organization_id::text,
				'user_id', om.user_id::text,
				'roles', (
					SELECT json_agg(json_build_object(
						'id', r.id::text,
						'name', r.name,
						'permissions', r.permissions
					))
					FROM organization_membership_roles omr
					JOIN organization_roles r ON omr.organization_role_id = r.id
					WHERE omr.organization_membership_id = om.id
				),
				'organization', (
					SELECT json_build_object(
						'id', o.id::text,
						'name', o.name,
						'description', o.description,
						'image_url', o.image_url,
						'member_count', o.member_count,
						'whitelisted_ips', o.whitelisted_ips,
						'auto_assigned_workspace_id', o.auto_assigned_workspace_id::text,
						'enforce_mfa', o.enforce_mfa_setup,
						'enable_ip_restriction', o.enable_ip_restriction,
						'public_metadata', o.public_metadata
					)
					FROM organizations o
					WHERE o.id = om.organization_id
				)
			)
			FROM organization_memberships om
			WHERE om.organization_id = ? AND om.user_id = ? AND om.deleted_at IS NULL
		`, orgID, *session.ActiveSignin.UserID).Scan(&membershipJSON).Error; err != nil {
			return handler.SendInternalServerError(c, err, "Failed to fetch organization membership")
		}

		if len(membershipJSON) == 0 {
			return handler.SendForbidden(c, nil, "You are not a member of this organization")
		}

		if err := json.Unmarshal([]byte(membershipJSON), membership); err != nil {
			return handler.SendInternalServerError(c, err, "Failed to parse organization membership")
		}
		org = membership.Organization
	}

	if org == nil {
		return handler.SendInternalServerError(c, nil, "Organization details missing")
	}

	d := handler.GetDeployment(c)
	clientIP := c.IP()

	if d.B2BSettings.IpAllowlistPerOrgEnabled && org.EnableIPRestriction && len(org.WhitelistedIPs) > 0 {
		if err := checkIPAllowlist(c, clientIP, org.WhitelistedIPs); err != nil {
			return err
		}
	}

	shouldEnforceMFA := false
	if org != nil && org.EnforceMFASetup {
		shouldEnforceMFA = true
	}

	if shouldEnforceMFA {
		user := session.ActiveSignin.User
		if user != nil {
			if user.UserAuthenticator == nil && !user.BackupCodesGenerated {
				return handler.SendForbidden(
					c,
					nil,
					"MFA is required for this organization",
					handler.ErrMfaRequired,
				)
			}
		}
	}

	c.Locals("membership", *membership)
	c.Locals("organization", *org)

	return c.Next()
}
