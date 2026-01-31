package middleware

import (
	"encoding/json"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
)

func SetWorkspaceContext(c *fiber.Ctx) error {
	workspaceIDStr := c.Params("id")
	if workspaceIDStr == "" {
		workspaceIDStr = c.Params("workspaceId")
	}

	if workspaceIDStr == "" {
		return c.Next()
	}

	workspaceID, err := strconv.ParseUint(workspaceIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid workspace ID")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	type membershipData struct {
		model.WorkspaceMembership
		RolesJSON        string `gorm:"column:roles_json"`
		WorkspaceJSON    string `gorm:"column:workspace_json"`
		OrganizationJSON string `gorm:"column:organization_json"`
	}
	var data membershipData

	rawSQL := `
		SELECT
			wm.id,
			wm.workspace_id,
			wm.user_id,
			wm.organization_id,
			wm.organization_membership_id,
			COALESCE(wm.public_metadata::text, '{}') as public_metadata,
			wm.created_at,
			wm.updated_at,
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', wr.id::text,
						'name', wr.name,
						'permissions', wr.permissions
					) ORDER BY wr.name
				)
				FROM workspace_membership_roles wmr
				JOIN workspace_roles wr ON wmr.workspace_role_id = wr.id
				WHERE wmr.workspace_membership_id = wm.id
				), '[]'::json
			) as roles_json,
			(
				SELECT json_build_object(
					'id', w.id::text,
					'name', w.name,
					'description', w.description,
					'image_url', w.image_url,
					'member_count', w.member_count,
					'whitelisted_ips', w.whitelisted_ips,
					'enforce_2fa', w.enforce_mfa_setup,
					'enable_ip_restriction', w.enable_ip_restriction,
					'public_metadata', w.public_metadata
				)
				FROM workspaces w
				WHERE w.id = wm.workspace_id
			) as workspace_json,
			(
				SELECT json_build_object(
					'id', o.id::text,
					'name', o.name,
					'image_url', o.image_url,
					'description', o.description,
					'member_count', o.member_count,
					'whitelisted_ips', o.whitelisted_ips,
					'enable_ip_restriction', o.enable_ip_restriction,
					'enforce_mfa', o.enforce_mfa_setup,
					'public_metadata', o.public_metadata
				)
				FROM organizations o
				WHERE o.id = wm.organization_id
			) as organization_json
		FROM workspace_memberships wm
		WHERE wm.workspace_id = ? AND wm.user_id = ? AND wm.deleted_at IS NULL
		LIMIT 1
	`

	if err := database.Connection.Raw(rawSQL, workspaceID, session.ActiveSignin.UserID).Scan(&data).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to load workspace membership")
	}

	membership := data.WorkspaceMembership
	// Unmarshal JSON fields
	if data.RolesJSON != "" && data.RolesJSON != "[]" {
		json.Unmarshal([]byte(data.RolesJSON), &membership.Roles)
	}
	if data.WorkspaceJSON != "" {
		var w model.PublicWorkspaceData
		if err := json.Unmarshal([]byte(data.WorkspaceJSON), &w); err == nil {
			membership.Workspace = &w
		}
	}
	if data.OrganizationJSON != "" {
		var o model.PublicOrganizationData
		if err := json.Unmarshal([]byte(data.OrganizationJSON), &o); err == nil {
			membership.Organization = &o
		}
	}

	if membership.ID == 0 || membership.Workspace == nil {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this workspace")
	}

	// B2B Settings Enforcement
	d := handler.GetDeployment(c)
	clientIP := c.IP()

	// 1. IP Restriction - Organization Level
	if membership.Organization != nil && d.B2BSettings.IpAllowlistPerOrgEnabled && membership.Organization.EnableIPRestriction && len(membership.Organization.WhitelistedIPs) > 0 {
		if err := checkIPAllowlist(c, clientIP, membership.Organization.WhitelistedIPs); err != nil {
			return err
		}
	}

	// 2. IP Restriction - Workspace Level
	if d.B2BSettings.IpAllowlistPerWorkspaceEnabled && membership.Workspace.EnableIPRestriction && len(membership.Workspace.WhitelistedIPs) > 0 {
		if err := checkIPAllowlist(c, clientIP, membership.Workspace.WhitelistedIPs); err != nil {
			return err
		}
	}

	// 3. MFA Enforcement - check in order: Org level, Workspace level, User policy
	shouldEnforceMFA := false
	if membership.Organization != nil && d.B2BSettings.EnforceMfaPerOrgEnabled && membership.Organization.EnforceMFASetup {
		shouldEnforceMFA = true
	}
	if d.B2BSettings.EnforceMfaPerWorkspaceEnabled && membership.Workspace.EnforceMFASetup {
		shouldEnforceMFA = true
	}
	if session.ActiveSignin.User != nil && session.ActiveSignin.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced {
		shouldEnforceMFA = true
	}

	if shouldEnforceMFA {
		// Check if user has MFA setup using session data
		user := session.ActiveSignin.User
		if user != nil {
			if user.UserAuthenticator == nil && !user.BackupCodesGenerated {
				return handler.SendForbidden(c, fiber.Map{
					"code":    "mfa_required",
					"message": "Multi-factor authentication is required to access this workspace.",
				}, "MFA required")
			}
		}
	}

	c.Locals("workspace_membership", membership)
	c.Locals("workspace", membership.Workspace)
	c.Locals("organization", membership.Organization)

	return c.Next()
}
