package organization

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lib/pq"

	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
	"github.com/wacht-platform/frontend-api/service"
	"github.com/wacht-platform/frontend-api/utils"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Handler struct {
	service *OrgService
}

func NewHandler() *Handler {
	return &Handler{
		service: NewOrgService(),
	}
}

func getuint64(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		panic("invalid organization id")
	}
	return uint64(v)
}

func (h *Handler) CreateOrganization(
	c fiber.Ctx,
) error {
	d := handler.GetDeployment(c)
	b, validation := handler.Validate[CreateOrgRequest](c)
	img, _ := c.FormFile("image")
	imgurl := d.UISettings.DefaultOrganizationProfileImageURL
	orgid := idgen.NextID()

	if !d.B2BSettings.OrganizationsEnabled {
		return handler.SendBadRequest(c, nil, "Organizations are not enabled for this deployment")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	if d.B2BSettings.LimitOrgCreationPerUser {
		var orgCount int64
		if err := database.Connection.Model(&model.OrganizationMembership{}).
			Where("user_id = ?", session.ActiveSignin.UserID).
			Joins("JOIN organization_membership_roles ON organization_membership_roles.organization_membership_id = organization_memberships.id").
			Where("organization_membership_roles.organization_role_id = ?", d.B2BSettings.DefaultOrgCreatorRoleID).
			Count(&orgCount).Error; err != nil {
			return handler.SendInternalServerError(c, err, "Failed to check organization limits")
		}

		if d.B2BSettings.MaxOrgsPerUser > 0 && orgCount >= int64(d.B2BSettings.MaxOrgsPerUser) {
			return handler.SendForbidden(
				c,
				nil,
				fmt.Sprintf(
					"You have reached the maximum number of organizations allowed (%d)",
					d.B2BSettings.MaxOrgsPerUser,
				),
			)
		}
	}

	if img != nil {
		url, err := h.service.uploadOrganizationImage(orgid, img)
		if err != nil {
			log.Println(err)
			return handler.SendInternalServerError(c, err, "Failed to upload organization image")
		}
		imgurl = url
	}

	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	org := model.Organization{
		Model: model.Model{
			ID: orgid,
		},
		DeploymentID: d.ID,
		Name:         b.Name,
		Description:  b.Description,
		ImageUrl:     imgurl,
	}

	membership := model.OrganizationMembership{
		Model: model.Model{
			ID: idgen.NextID(),
		},
		OrganizationID: orgid,
		UserID:         *session.ActiveSignin.UserID,
	}

	rawSQL := `
		WITH inserted_org AS (
			INSERT INTO organizations (
				id, deployment_id, name, description, image_url, member_count,
				enforce_mfa_setup, enable_ip_restriction, created_at, updated_at,
				public_metadata, private_metadata
			) VALUES (?, ?, ?, ?, ?, 1, false, false, NOW(), NOW(), '{}', '{}')
			RETURNING id
		),
		inserted_membership AS (
			INSERT INTO organization_memberships (
				id, organization_id, user_id, created_at, updated_at
			) VALUES (?, ?, ?, NOW(), NOW())
			RETURNING id
		),
		inserted_roles AS (
			INSERT INTO organization_membership_roles (
				organization_membership_id, organization_role_id, organization_id
			) VALUES (?, ?, ?)
			RETURNING organization_id
		)
		UPDATE signins
		SET active_organization_membership_id = ?
		FROM inserted_org, inserted_membership, inserted_roles
		WHERE signins.id = ?;
	`
	if err := database.Connection.Exec(
		rawSQL,
		org.ID, d.ID, org.Name, org.Description, org.ImageUrl,
		membership.ID, org.ID, membership.UserID,
		membership.ID, d.B2BSettings.DefaultOrgCreatorRoleID, org.ID,
		membership.ID, session.ActiveSignin.ID,
	).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create organization")
	}

	session.ActiveSignin.ActiveOrganizationMembershipID = &membership.ID

	utils.PublishWebhookEvent(d.ID, "organization.created", org.ID, "organization")

	database.SyncUserWrapper(database.Connection, *session.ActiveSignin.UserID, "organization.created")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, CreateOrganizationResponse{
		Organization: org,
		Membership:   membership,
	})
}

func (h *Handler) LeaveOrganization(
	c fiber.Ctx,
) error {
	orgIDStr := c.Params("id")
	orgID := getuint64(orgIDStr)
	session := handler.GetSession(c)
	d := handler.GetDeployment(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	isOwner := h.service.hasPermission(membership, orgOwnerPermissions)
	if isOwner {
		var adminCount int64
		if err := database.Connection.Table("organization_membership_roles").
			Where("organization_id = ? AND organization_role_id = ? AND organization_membership_id != ?",
				orgID,
				d.B2BSettings.DefaultOrgCreatorRoleID,
				membership.ID).
			Count(&adminCount).Error; err != nil {
			log.Println(
				"Error counting other admins using DefaultOrgCreatorRoleID on organization_membership_roles:",
				err,
			)
			return handler.SendInternalServerError(c, err, "Failed to verify organization admin status")
		}

		if adminCount == 0 {
			return handler.SendForbidden(
				c,
				nil,
				"Cannot leave organization as the sole admin. Please transfer ownership or assign this role to another member first.",
			)
		}
	}

	err := database.Connection.Transaction(
		func(tx *gorm.DB) error {
			if err := tx.Where("organization_membership_id = ?", membership.ID).
				Delete(&model.WorkspaceMembership{}).Error; err != nil {
				return err
			}

			if err := tx.Delete(&membership).Error; err != nil {
				return err
			}

			if session.ActiveSignin.ActiveOrganizationMembershipID != nil &&
				*session.ActiveSignin.ActiveOrganizationMembershipID == membership.ID {
				session.ActiveSignin.ActiveOrganizationMembershipID = nil
				session.ActiveSignin.ActiveWorkspaceMembershipID = nil
				if errDb := database.Connection.Model(&model.Signin{}).Where("id = ?", session.ActiveSignin.ID).Updates(map[string]any{
					"active_organization_membership_id": nil,
					"active_workspace_membership_id":    nil,
				}).Error; errDb != nil {
					log.Printf(
						"Failed to clear active organization ID for user %d: %v",
						session.ActiveSignin.UserID,
						errDb,
					)
				}
			}

			return nil
		},
	)

	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to leave organization")
	}

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	database.SyncUserWrapper(database.Connection, *session.ActiveSignin.UserID, "organization.left")

	return handler.SendSuccess(c, handler.SuccessResponse{Success: true})
}

func (h *Handler) UpdateOrganization(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	b, validation := handler.Validate[UpdateOrgRequest](c)
	if validation != nil {
		log.Println(validation)
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions to update organization.")
	}

	org := membership.Organization

	if img, _ := c.FormFile("image"); img != nil {
		url, err := h.service.uploadOrganizationImage(getuint64(orgID), img)
		if err != nil {
			log.Println(err)
			return handler.SendInternalServerError(c, err, "Failed to upload organization image")
		}

		org.ImageUrl = url
	} else if c.FormValue("image") == "null" {
		org.ImageUrl = ""
	}

	if b.Name != nil {
		org.Name = *b.Name
	}

	if b.Description != nil {
		org.Description = *b.Description
	}

	if len(b.WhitelistedIPs) > 0 {
		org.WhitelistedIPs = b.WhitelistedIPs
	}

	if b.AutoAssignedWorkspaceID != nil {
		if *b.AutoAssignedWorkspaceID == 0 {
			org.AutoAssignedWorkspaceID = nil
		} else {
			org.AutoAssignedWorkspaceID = b.AutoAssignedWorkspaceID
		}
	}

	if b.EnforceMFASetup != nil {
		org.EnforceMFASetup = *b.EnforceMFASetup
	}

	if b.EnableIPRestriction != nil {
		org.EnableIPRestriction = *b.EnableIPRestriction
	}

	if err := database.Connection.Save(&org).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to update organization")
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "organization.updated", org.ID, "organization")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, org)
}

func (h *Handler) DeleteOrganization(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	session := handler.GetSession(
		c,
	)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	log.Println(membership.Roles)
	hasPermission := h.service.hasPermission(membership, orgOwnerPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Only organization owner can delete the organization")
	}

	orgIDUint, err := strconv.ParseUint(orgID, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid organization id")
	}
	deployment := handler.GetDeployment(c)

	rawSQL := `
		DELETE FROM workspace_membership_roles WHERE organization_id = ?;
		DELETE FROM workspace_memberships WHERE organization_id = ?;
		DELETE FROM workspace_roles WHERE organization_id = ?;
		DELETE FROM workspaces WHERE organization_id = ?;
		DELETE FROM organization_membership_roles WHERE organization_id = ?;
		DELETE FROM organization_memberships WHERE organization_id = ?;
		DELETE FROM organization_invitations WHERE organization_id = ?;
		DELETE FROM scim_group_members WHERE scim_group_id IN (SELECT id FROM scim_groups WHERE organization_id = ?);
		DELETE FROM scim_groups WHERE organization_id = ?;
		DELETE FROM scim_tokens WHERE organization_id = ?;
		DELETE FROM enterprise_connections WHERE organization_id = ?;
		DELETE FROM organization_domains WHERE organization_id = ?;
		DELETE FROM organization_roles WHERE organization_id = ?;
		DELETE FROM organizations WHERE id = ?;
	`

	if err := database.Connection.Exec(
		rawSQL,
		orgIDUint, orgIDUint, orgIDUint, orgIDUint, orgIDUint, orgIDUint, orgIDUint,
		orgIDUint, orgIDUint, orgIDUint, orgIDUint, orgIDUint, orgIDUint, orgIDUint,
	).Error; err != nil {
		log.Printf("Failed to delete organization %s: %v", orgID, err)
		return handler.SendInternalServerError(c, err, "Failed to delete organization")
	}

	utils.PublishWebhookEvent(deployment.ID, "organization.deleted", orgIDUint, "organization")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, handler.SuccessResponse{Success: true})
}

func (h *Handler) GetOrganizationInvitations(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	// DEBUG: Start timing
	funcStart := time.Now()
	log.Printf("[DEBUG] GetOrganizationInvitations: Starting fetch for OrgID: %s", orgID)
	defer func() {
		log.Printf("[DEBUG] GetOrganizationInvitations: Total time: %v", time.Since(funcStart))
	}()

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var queryResults []OrganizationInvitationQueryResult
	dbStart := time.Now()

	workspaceID := c.Query("workspace_id")
	whereClause := "organization_invitations.organization_id = ? AND organization_invitations.deleted_at IS NULL"
	args := []interface{}{orgID}

	if workspaceID != "" {
		whereClause += " AND organization_invitations.workspace_id = ?"
		args = append(args, workspaceID)
	}

	rawSQL := `
		SELECT
			organization_invitations.*,
			CASE WHEN organization_roles.id IS NOT NULL THEN
				json_build_object(
					'id', organization_roles.id::text,
					'name', organization_roles.name,
					'permissions', organization_roles.permissions
				)
			ELSE '{}'::json END as initial_organization_role_json,
			CASE WHEN workspace_roles.id IS NOT NULL THEN
				json_build_object(
					'id', workspace_roles.id::text,
					'name', workspace_roles.name
				)
			ELSE '{}'::json END as initial_workspace_role_json,
			CASE WHEN workspaces.id IS NOT NULL THEN
				json_build_object(
					'id', workspaces.id::text,
					'name', workspaces.name
				)
			ELSE '{}'::json END as workspace_json,
			json_build_object(
				'id', inviter_user.id::text,
				'first_name', inviter_user.first_name,
				'last_name', inviter_user.last_name,
				'username', inviter_user.username,
				'profile_picture_url', inviter_user.profile_picture_url,
				'has_profile_picture', inviter_user.has_profile_picture,
				'availability', inviter_user.availability,
				'public_metadata', COALESCE(inviter_user.public_metadata, '{}'),
				'created_at', inviter_user.created_at,
				'updated_at', inviter_user.updated_at,
				'primary_email_address', CASE
					WHEN inviter_email.id IS NOT NULL THEN json_build_object(
						'id', inviter_email.id::text,
						'email', inviter_email.email_address,
						'is_primary', inviter_email.is_primary,
						'verified', inviter_email.verified
					)
					ELSE NULL
				END
			) as inviter_user_json,
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', inviter_roles.id::text,
						'organization_id', CASE WHEN inviter_roles.organization_id IS NOT NULL THEN inviter_roles.organization_id::text ELSE NULL END,
						'name', inviter_roles.name,
						'permissions', inviter_roles.permissions,
						'deployment_id', inviter_roles.deployment_id::text,
						'created_at', inviter_roles.created_at,
						'updated_at', inviter_roles.updated_at
					) ORDER BY inviter_roles.name
				)
				FROM organization_membership_roles omr
				JOIN organization_roles inviter_roles ON omr.organization_role_id = inviter_roles.id
				WHERE omr.organization_membership_id = inviter_membership.id
				), '[]'::json
			) as inviter_roles_json,
			COALESCE(inviter_membership.public_metadata::text, '{}') as inviter_public_metadata_json
		FROM organization_invitations
		LEFT JOIN organization_roles ON organization_invitations.initial_organization_role_id = organization_roles.id
		LEFT JOIN workspace_roles ON organization_invitations.initial_workspace_role_id = workspace_roles.id
		LEFT JOIN workspaces ON organization_invitations.workspace_id = workspaces.id
		LEFT JOIN organization_memberships AS inviter_membership ON organization_invitations.inviter_id = inviter_membership.id
		LEFT JOIN users AS inviter_user ON inviter_membership.user_id = inviter_user.id
		LEFT JOIN user_email_addresses AS inviter_email ON inviter_user.primary_email_address_id = inviter_email.id
		WHERE ` + whereClause + `
		ORDER BY organization_invitations.created_at DESC
	`

	if err := database.Connection.Raw(rawSQL, args...).Scan(&queryResults).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to fetch invitations")
	}

	invitations := make([]model.OrganizationInvitation, len(queryResults))
	for i, result := range queryResults {
		invitations[i] = result.OrganizationInvitation

		if result.InitialOrganizationRoleJSON != "" && result.InitialOrganizationRoleJSON != "{}" {
			var role model.OrganizationRole
			if err := json.Unmarshal([]byte(result.InitialOrganizationRoleJSON), &role); err == nil {
				invitations[i].InitialOrganizationRole = role
			}
		}

		if result.InitialWorkspaceRoleJSON != "" && result.InitialWorkspaceRoleJSON != "{}" {
			var role model.WorkspaceRole
			if err := json.Unmarshal([]byte(result.InitialWorkspaceRoleJSON), &role); err == nil {
				invitations[i].InitialWorkspaceRole = role
			}
		}

		if result.WorkspaceJSON != "" && result.WorkspaceJSON != "{}" {
			var ws model.Workspace
			if err := json.Unmarshal([]byte(result.WorkspaceJSON), &ws); err == nil {
				invitations[i].Workspace = ws
			}
		}

		// Populate Inviter
		// We set IDs from the invitation relation, but we also populate the object
		invitations[i].Inviter.ID = invitations[i].InviterID
		invitations[i].Inviter.OrganizationID = invitations[i].OrganizationID // Reuse org ID

		if result.InviterUserJSON != "" {
			var userData model.PublicUserData
			if err := json.Unmarshal([]byte(result.InviterUserJSON), &userData); err == nil {
				invitations[i].Inviter.User = &userData
			}
		}

		if result.InviterRolesJSON != "" && result.InviterRolesJSON != "[]" {
			var roles []*model.OrganizationRole
			if err := json.Unmarshal([]byte(result.InviterRolesJSON), &roles); err == nil {
				invitations[i].Inviter.Roles = roles
			}
		}

		if result.InviterPublicMetadataJSON != "" && result.InviterPublicMetadataJSON != "{}" && result.InviterPublicMetadataJSON != "null" {
			var metadata datatypes.JSONMap
			if err := json.Unmarshal([]byte(result.InviterPublicMetadataJSON), &metadata); err == nil {
				invitations[i].Inviter.PublicMetadata = metadata
			} else {
				invitations[i].Inviter.PublicMetadata = make(datatypes.JSONMap)
			}
		} else {
			invitations[i].Inviter.PublicMetadata = make(datatypes.JSONMap)
		}
	}

	log.Printf("[DEBUG] GetOrganizationInvitations: Raw SQL Query took %v for %d invitations", time.Since(dbStart), len(invitations))

	return handler.SendSuccess(c, invitations)
}

func (h *Handler) InviteMember(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	b, validation := handler.Validate[InviteMemberRequest](
		c,
	)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	b.Email = strings.ToLower(strings.TrimSpace(b.Email))

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	tokenBase, err := utils.GenerateSecureToken(32)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to generate invitation token")
	}
	token := fmt.Sprintf("org.%s", tokenBase)

	if d := handler.GetDeployment(c); d.B2BSettings.MaxAllowedOrgMembers > 0 {
		var memberCount int64
		if err := database.Connection.Model(&model.OrganizationMembership{}).
			Where("organization_id = ?", orgID).
			Count(&memberCount).Error; err != nil {
			return handler.SendInternalServerError(c, err, "Failed to check member limits")
		}

		// Count pending invitations as well
		var inviteCount int64
		if err := database.Connection.Model(&model.OrganizationInvitation{}).
			Where("organization_id = ?", orgID).
			Count(&inviteCount).Error; err != nil {
			return handler.SendInternalServerError(c, err, "Failed to check invitation limits")
		}

		if uint64(memberCount+inviteCount) >= d.B2BSettings.MaxAllowedOrgMembers {
			return handler.SendForbidden(
				c,
				nil,
				fmt.Sprintf(
					"Organization has reached the maximum number of members allowed (%d)",
					d.B2BSettings.MaxAllowedOrgMembers,
				),
			)
		}
	}

	invitation := model.OrganizationInvitation{
		Model: model.Model{
			ID: idgen.NextID(),
		},
		OrganizationID: getuint64(orgID),
		InviterID:      membership.ID,
		Email:          b.Email,
		Token:          token,
	}

	if b.RoleID != nil {
		invitation.InitialOrganizationRoleID = b.RoleID
	}

	deployment := handler.GetDeployment(c)

	if b.WorkspaceID == nil {
		var checkResult struct {
			HasPendingInvite bool
			IsMember         bool
		}
		database.Connection.Raw(`
			SELECT
				EXISTS(
					SELECT 1 FROM organization_invitations
					WHERE email = ? AND organization_id = ? AND workspace_id IS NULL AND deleted_at IS NULL
				) as has_pending_invite,
				EXISTS(
					SELECT 1 FROM organization_memberships om
					JOIN user_email_addresses uea ON uea.user_id = om.user_id
					WHERE uea.email_address = ? AND uea.deployment_id = ?
					AND om.organization_id = ? AND om.deleted_at IS NULL
				) as is_member
		`, b.Email, getuint64(orgID), b.Email, deployment.ID, getuint64(orgID)).Scan(&checkResult)

		if checkResult.HasPendingInvite {
			return handler.SendBadRequest(c, nil, "An invitation for this email is already pending")
		}
		if checkResult.IsMember {
			return handler.SendBadRequest(c, nil, "User is already a member of this organization")
		}
	}

	if b.WorkspaceID != nil {
		invitation.WorkspaceID = b.WorkspaceID

		var wsCheckResult struct {
			HasPendingInvite bool
			IsMember         bool
		}
		database.Connection.Raw(`
			SELECT
				EXISTS(
					SELECT 1 FROM organization_invitations
					WHERE email = ? AND workspace_id = ? AND organization_id = ? AND deleted_at IS NULL
				) as has_pending_invite,
				EXISTS(
					SELECT 1 FROM workspace_memberships wm
					JOIN user_email_addresses uea ON uea.user_id = wm.user_id
					WHERE uea.email_address = ? AND uea.deployment_id = ?
					AND wm.workspace_id = ? AND wm.deleted_at IS NULL
				) as is_member
		`, b.Email, *b.WorkspaceID, getuint64(orgID), b.Email, deployment.ID, *b.WorkspaceID).Scan(&wsCheckResult)

		if wsCheckResult.HasPendingInvite {
			return handler.SendBadRequest(c, nil, "An invitation for this email and workspace is already pending")
		}
		if wsCheckResult.IsMember {
			return handler.SendBadRequest(c, nil, "User is already a member of this workspace")
		}

		if deployment.B2BSettings.MaxAllowedWorkspaceMembers > 0 {
			var wsMemberCount int64
			if err := database.Connection.Model(&model.WorkspaceMembership{}).
				Where("workspace_id = ?", *b.WorkspaceID).
				Count(&wsMemberCount).Error; err != nil {
				return handler.SendInternalServerError(c, err, "Failed to check workspace member limits")
			}

			var wsInviteCount int64
			if err := database.Connection.Model(&model.OrganizationInvitation{}).
				Where("workspace_id = ? AND deleted_at IS NULL", *b.WorkspaceID).
				Count(&wsInviteCount).Error; err != nil {
				return handler.SendInternalServerError(c, err, "Failed to check workspace invitation limits")
			}

			if uint64(wsMemberCount+wsInviteCount) >= deployment.B2BSettings.MaxAllowedWorkspaceMembers {
				return handler.SendForbidden(
					c,
					nil,
					fmt.Sprintf(
						"Workspace has reached the maximum number of members allowed (%d)",
						deployment.B2BSettings.MaxAllowedWorkspaceMembers,
					),
				)
			}
		}
	}

	if b.WorkspaceRoleID != nil {
		invitation.InitialWorkspaceRoleID = b.WorkspaceRoleID
	}

	if err := database.Connection.Create(&invitation).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to invite member")
	}

	var organization model.Organization
	database.Connection.First(&organization, getuint64(orgID))

	var inviterUser model.User
	if membership.UserID != 0 {
		database.Connection.First(&inviterUser, membership.UserID)
	}

	inviteLink := fmt.Sprintf("https://%s/invite?token=%s", deployment.FrontendHost, token)

	inviterName := fmt.Sprintf("%s %s", inviterUser.FirstName, inviterUser.LastName)
	if inviterName == " " {
		inviterName = inviterUser.Username
	}

	err = h.service.nats.SendOrganizationInviteEmail(
		deployment.ID,
		b.Email,
		inviterName,
		organization.Name,
		inviteLink,
	)

	if err != nil {
		log.Printf("Failed to send invitation email: %v", err)
	}

	utils.PublishWebhookEvent(
		deployment.ID,
		"organization.invitation.created",
		invitation.ID,
		"organization_invitation",
	)

	return handler.SendSuccess(c, invitation)
}

func (h *Handler) DiscardInvitation(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	invitationID := c.Params("invitationId")
	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	invitationIDUint := getuint64(invitationID)
	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(
		deployment.ID,
		"organization.invitation.revoked",
		invitationIDUint,
		"organization_invitation",
	)

	if err := database.Connection.Delete(&model.OrganizationInvitation{
		Model: model.Model{
			ID: invitationIDUint,
		},
		OrganizationID: getuint64(orgID),
	}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to dismiss invitation")
	}

	return handler.SendSuccess(c, handler.SuccessResponse{Success: true})
}

func (h *Handler) ResendInvitation(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	invitationID := c.Params("invitationId")
	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	invitationIDUint := getuint64(invitationID)
	var invitation model.OrganizationInvitation
	if err := database.Connection.
		Where("id = ? AND organization_id = ?", invitationIDUint, getuint64(orgID)).
		First(&invitation).Error; err != nil {
		return handler.SendNotFound(c, nil, "Invitation not found")
	}

	// Generate new token and reset expiry
	tokenBase, err := utils.GenerateSecureToken(32)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to generate invitation token")
	}
	invitation.Token = fmt.Sprintf("org.%s", tokenBase)
	invitation.Expiry = time.Now().Add(10 * 24 * time.Hour)

	if err := database.Connection.Save(&invitation).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to update invitation")
	}

	deployment := handler.GetDeployment(c)
	var organization model.Organization
	database.Connection.First(&organization, invitation.OrganizationID)

	var inviterMembership model.OrganizationMembership
	database.Connection.Preload("User").First(&inviterMembership, invitation.InviterID)
	inviterUser := inviterMembership.User

	inviteLink := fmt.Sprintf("https://%s/invite?token=%s", deployment.FrontendHost, invitation.Token)

	inviterName := fmt.Sprintf("%s %s", inviterUser.FirstName, inviterUser.LastName)
	if inviterName == " " {
		inviterName = inviterUser.Username
	}

	err = h.service.nats.SendOrganizationInviteEmail(
		deployment.ID,
		invitation.Email,
		inviterName,
		organization.Name,
		inviteLink,
	)

	if err != nil {
		log.Printf("Failed to send invitation email: %v", err)
	}

	return handler.SendSuccess(c, invitation)
}

func (h *Handler) AcceptInvitation(
	c fiber.Ctx,
) error {
	b, validation := handler.Validate[AcceptInvitationRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Invalid request")
	}

	session := handler.GetSession(c)

	var invitation model.OrganizationInvitation
	if err := database.Connection.
		Where("token = ?", b.Token).
		First(&invitation).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Invalid or expired invitation", handler.Error{
			Code:    handler.ErrCodeInvalidInvitationToken,
			Message: "The invitation token is invalid or does not exist",
		})
	}

	if invitation.Expiry.Before(time.Now()) {
		response := AcceptInvitationResponse{
			Message:      "This invitation has expired. Please request a new invitation.",
			InvitedEmail: invitation.Email,
			ErrorCode:    handler.ErrCodeInvitationExpired,
		}
		return handler.SendSuccess(c, response)
	}

	var org model.Organization
	if err := database.Connection.First(&org, invitation.OrganizationID).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to fetch organization")
	}

	var emailAddress model.UserEmailAddress
	invitedEmail := strings.ToLower(strings.TrimSpace(invitation.Email))
	userExists := true
	if err := database.Connection.
		Where("email_address = ? AND deployment_id = ?", invitedEmail, org.DeploymentID).
		Preload("User").
		First(&emailAddress).Error; err != nil {
		userExists = false
	}

	if session.ActiveSignin == nil || len(session.Signins) == 0 {
		if userExists {
			response := AcceptInvitationResponse{
				Message:        "Please sign in to accept this invitation",
				RequiresSignin: true,
				InvitedEmail:   invitation.Email,
				ErrorCode:      handler.ErrCodeInvitationRequiresSignin,
			}
			return handler.SendSuccess(c, response)
		} else {
			response := AcceptInvitationResponse{
				Message:        "Please sign up to accept this invitation",
				RequiresSignin: true,
				InvitedEmail:   invitation.Email,
				ErrorCode:      handler.ErrCodeInvitationRequiresSignup,
			}
			return handler.SendSuccess(c, response)
		}
	}

	if !userExists {
		response := AcceptInvitationResponse{
			Message:        fmt.Sprintf("No account exists with email %s. Please sign up with that email first.", invitation.Email),
			RequiresSignin: true,
			InvitedEmail:   invitation.Email,
			ErrorCode:      handler.ErrCodeInvitationRequiresSignup,
		}
		return handler.SendSuccess(c, response)
	}

	var matchingSignin *model.Signin
	for _, signin := range session.Signins {
		if signin.UserID != nil && emailAddress.UserID != nil && *signin.UserID == *emailAddress.UserID {
			matchingSignin = &signin
			break
		}
	}

	if matchingSignin == nil {
		response := AcceptInvitationResponse{
			Message:        fmt.Sprintf("Please sign in with %s to accept this invitation", invitation.Email),
			RequiresSignin: true,
			InvitedEmail:   invitation.Email,
			ErrorCode:      handler.ErrCodeInvitationEmailMismatch,
		}
		return handler.SendSuccess(c, response)
	}

	var existingMembership model.OrganizationMembership
	err := database.Connection.
		Where("organization_id = ? AND user_id = ?", invitation.OrganizationID, *emailAddress.UserID).
		First(&existingMembership).Error

	if err == nil {
		if invitation.WorkspaceID != nil {
			var existingWorkspaceMembership model.WorkspaceMembership
			if database.Connection.
				Where("workspace_id = ? AND user_id = ?", *invitation.WorkspaceID, *emailAddress.UserID).
				First(&existingWorkspaceMembership).Error == nil {
				database.Connection.Delete(&invitation)
				return handler.SendSuccess(c, AcceptInvitationResponse{
					Organization: OrganizationInfo{
						ID:   fmt.Sprintf("%d", org.ID),
						Name: org.Name,
					},
					SigninID:      fmt.Sprintf("%d", matchingSignin.ID),
					AlreadyMember: true,
					Message:       "You are already a member of this workspace",
				})
			}

			var workspace model.Workspace
			database.Connection.First(&workspace, *invitation.WorkspaceID)

			txErr := database.Connection.Transaction(func(tx *gorm.DB) error {
				workspaceMembership := model.WorkspaceMembership{
					Model: model.Model{
						ID: idgen.NextID(),
					},
					WorkspaceID:              *invitation.WorkspaceID,
					UserID:                   *emailAddress.UserID,
					OrganizationID:           invitation.OrganizationID,
					OrganizationMembershipID: existingMembership.ID,
				}

				if err := tx.Create(&workspaceMembership).Error; err != nil {
					return err
				}

				deployment := handler.GetDeployment(c)
				wsRoleID := invitation.InitialWorkspaceRoleID
				if wsRoleID == nil && deployment.B2BSettings.DefaultWorkspaceMemberRoleID != 0 {
					wsRoleID = &deployment.B2BSettings.DefaultWorkspaceMemberRoleID
				}
				if wsRoleID != nil {
					if err := tx.Exec(
						"INSERT INTO workspace_membership_roles (workspace_membership_id, workspace_role_id, workspace_id, organization_id) VALUES (?, ?, ?, ?)",
						workspaceMembership.ID,
						*wsRoleID,
						*invitation.WorkspaceID,
						invitation.OrganizationID,
					).Error; err != nil {
						return err
					}
				}

				return tx.Delete(&invitation).Error
			})

			if txErr != nil {
				return handler.SendInternalServerError(c, txErr, "Failed to accept invitation")
			}

			database.SyncUserWrapper(database.Connection, *emailAddress.UserID, "AcceptInvitation-Workspace")

			return handler.SendSuccess(c, AcceptInvitationResponse{
				Organization: OrganizationInfo{
					ID:   fmt.Sprintf("%d", org.ID),
					Name: org.Name,
				},
				Workspace: &WorkspaceInfo{
					ID:   fmt.Sprintf("%d", workspace.ID),
					Name: workspace.Name,
				},
				SigninID: fmt.Sprintf("%d", matchingSignin.ID),
				Message:  "You have been added to the workspace",
			})
		}

		database.Connection.Delete(&invitation)

		response := AcceptInvitationResponse{
			Organization: OrganizationInfo{
				ID:   fmt.Sprintf("%d", org.ID),
				Name: org.Name,
			},
			SigninID:      fmt.Sprintf("%d", matchingSignin.ID),
			AlreadyMember: true,
			Message:       "You are already a member of this organization",
		}

		return handler.SendSuccess(c, response)
	}

	membership := model.OrganizationMembership{
		Model: model.Model{
			ID: idgen.NextID(),
		},
		OrganizationID: invitation.OrganizationID,
		UserID:         *emailAddress.UserID,
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&membership).Error; err != nil {
			return err
		}

		deployment := handler.GetDeployment(c)
		orgRoleID := invitation.InitialOrganizationRoleID
		if orgRoleID == nil && deployment.B2BSettings.DefaultOrgMemberRoleID != 0 {
			orgRoleID = &deployment.B2BSettings.DefaultOrgMemberRoleID
		}
		if orgRoleID != nil {
			if err := tx.Exec(
				"INSERT INTO organization_membership_roles (organization_membership_id, organization_role_id, organization_id) VALUES (?, ?, ?)",
				membership.ID,
				*orgRoleID,
				invitation.OrganizationID,
			).Error; err != nil {
				return err
			}
		}

		if invitation.WorkspaceID != nil {
			workspaceMembership := model.WorkspaceMembership{
				Model: model.Model{
					ID: idgen.NextID(),
				},
				WorkspaceID:              *invitation.WorkspaceID,
				UserID:                   *emailAddress.UserID,
				OrganizationID:           invitation.OrganizationID,
				OrganizationMembershipID: membership.ID,
			}

			if err := tx.Create(&workspaceMembership).Error; err != nil {
				return err
			}

			wsRoleID := invitation.InitialWorkspaceRoleID
			if wsRoleID == nil && deployment.B2BSettings.DefaultWorkspaceMemberRoleID != 0 {
				wsRoleID = &deployment.B2BSettings.DefaultWorkspaceMemberRoleID
			}
			if wsRoleID != nil {
				if err := tx.Exec(
					"INSERT INTO workspace_membership_roles (workspace_membership_id, workspace_role_id, workspace_id, organization_id) VALUES (?, ?, ?, ?)",
					workspaceMembership.ID,
					*wsRoleID,
					*invitation.WorkspaceID,
					invitation.OrganizationID,
				).Error; err != nil {
					return err
				}
			}
		}

		if err := tx.Delete(&invitation).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to accept invitation")
	}

	database.SyncUserWrapper(database.Connection, *emailAddress.UserID, "AcceptInvitation-Organization")

	response := AcceptInvitationResponse{
		Organization: OrganizationInfo{
			ID:   fmt.Sprintf("%d", org.ID),
			Name: org.Name,
		},
		SigninID: fmt.Sprintf("%d", matchingSignin.ID),
		Message:  "Successfully joined the organization",
	}

	if invitation.WorkspaceID != nil {
		var workspace model.Workspace
		database.Connection.First(&workspace, *invitation.WorkspaceID)
		response.Workspace = &WorkspaceInfo{
			ID:   fmt.Sprintf("%d", workspace.ID),
			Name: workspace.Name,
		}
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(
		deployment.ID,
		"organization.invitation.accepted",
		invitation.ID,
		"organization_invitation",
	)
	utils.PublishWebhookEvent(deployment.ID, "organization.member.added", membership.ID, "organization_membership")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)
	database.SyncUserWrapper(database.Connection, *emailAddress.UserID, "organization.invitation.accepted")

	return handler.SendSuccess(c, response)
}

func (h *Handler) RemoveMember(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	memberID := c.Params("memberId")

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var membershipToRemove model.OrganizationMembership
	if err := database.Connection.Where("organization_id = ? AND id = ?", orgID, memberID).First(&membershipToRemove).Error; err != nil {
		return handler.SendNotFound(c, nil, "Member not found")
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(
		deployment.ID,
		"organization.member.removed",
		membershipToRemove.ID,
		"organization_membership",
	)

	if err := database.Connection.Exec(`
		WITH
		deleted_invitations AS (
			DELETE FROM organization_invitations WHERE inviter_id = ?
		),
		deleted_membership_roles AS (
			DELETE FROM organization_membership_roles WHERE organization_membership_id = ?
		),
		target_workspace_memberships AS (
			SELECT id FROM workspace_memberships WHERE organization_id = ? AND user_id = ?
		),
		deleted_ws_roles AS (
			DELETE FROM workspace_membership_roles WHERE workspace_membership_id IN (SELECT id FROM target_workspace_memberships)
		),
		deleted_ws_memberships AS (
			DELETE FROM workspace_memberships WHERE id IN (SELECT id FROM target_workspace_memberships)
		)
		DELETE FROM organization_memberships WHERE id = ?
	`, membershipToRemove.ID, membershipToRemove.ID, membershipToRemove.OrganizationID, membershipToRemove.UserID, membershipToRemove.ID).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to remove member")
	}

	database.SyncUserWrapper(database.Connection, membershipToRemove.UserID, "organization.member.removed")

	return handler.SendSuccess(c, handler.SuccessResponse{Success: true})
}

func (h *Handler) AddMemberRole(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	memberID := c.Params("memberId")
	roleID := c.Params("roleId")

	session := handler.GetSession(c)
	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions to manage roles.")
	}

	var err error

	var role model.OrganizationRole
	var assignedMember model.OrganizationMembership

	err = database.Connection.Where("id = ?", roleID).First(&role).Error
	if err != nil {
		log.Println(err)
		return handler.SendInternalServerError(c, err, "Failed to add role")
	}

	err = database.Connection.
		Where("organization_id = ? AND id = ?", orgID, memberID).
		First(&assignedMember).
		Error
	if err != nil {
		log.Println(err)
		return handler.SendInternalServerError(c, err, "Failed to add role")
	}

	err = database.Connection.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.OrgMembershipRoleAssoc{
		OrganizationMembershipID: assignedMember.ID,
		OrganizationRoleID:       role.ID,
		OrganizationID:           assignedMember.OrganizationID,
	}).Error

	if err != nil {
		log.Println(err)
		return handler.SendInternalServerError(c, err, "Failed to add role")
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(
		deployment.ID,
		"organization.member.role.updated",
		assignedMember.ID,
		"organization_membership",
	)

	if assignedMember.UserID == *session.ActiveSignin.UserID {
		handler.RemoveSessionFromCacheAndLocals(c, session.ID)
	}

	database.SyncUserWrapper(database.Connection, assignedMember.UserID, "organization.role.added")

	natsService := service.GetNATS()
	if err := natsService.PublishApiKeyOrgMembershipSync(assignedMember.ID); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to enqueue API key permission sync")
	}

	return handler.SendSuccess(c, handler.SuccessResponse{Success: true})
}

func (h *Handler) RemoveMemberRole(
	c fiber.Ctx,
) error {
	orgIDStr := c.Params("id")
	memberIDStr := c.Params("memberId")
	roleIDStr := c.Params("roleId")

	orgIDuint64 := getuint64(orgIDStr)
	targetMembershipIDuint64 := getuint64(memberIDStr)
	roleIDToRemoveuint64 := getuint64(roleIDStr)

	session := handler.GetSession(c)
	d := handler.GetDeployment(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	actingUserMembership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(actingUserMembership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions to manage roles.")
	}

	var targetMemberShip model.OrganizationMembership
	if err := database.Connection.Where("organization_id = ? AND id = ?", orgIDuint64, targetMembershipIDuint64).First(&targetMemberShip).Error; err != nil {
		log.Printf("Target membership ID %d not found in org %d: %v", targetMembershipIDuint64, orgIDuint64, err)
		return handler.SendNotFound(c, err, "Target member or organization not found.")
	}

	isAdminRoleBeingRemoved := (roleIDToRemoveuint64 == d.B2BSettings.DefaultOrgCreatorRoleID)
	isSelfRemoval := (targetMemberShip.UserID == *session.ActiveSignin.UserID)

	if isAdminRoleBeingRemoved && isSelfRemoval {
		var otherAdminCount int64
		if err := database.Connection.Table("organization_membership_roles").
			Where("organization_id = ? AND organization_role_id = ? AND organization_membership_id != ?",
				orgIDuint64,
				d.B2BSettings.DefaultOrgCreatorRoleID,
				targetMembershipIDuint64).
			Count(&otherAdminCount).Error; err != nil {
			log.Println("Error counting other admins in RemoveMemberRole:", err)
			return handler.SendInternalServerError(c, err, "Failed to verify organization admin status.")
		}

		if otherAdminCount == 0 {
			return handler.SendForbidden(
				c,
				nil,
				"Cannot remove your own admin role as you are the sole admin. Please assign this role to another member first.",
			)
		}
	}

	if err := database.Connection.Exec(
		"DELETE FROM organization_membership_roles WHERE organization_membership_id = ? AND organization_role_id = ? AND organization_id = ?",
		targetMembershipIDuint64,
		roleIDToRemoveuint64,
		orgIDuint64,
	).Error; err != nil {
		log.Println("Failed to delete role from organization_membership_roles:", err)
		return handler.SendInternalServerError(c, err, "Failed to remove role.")
	}

	utils.PublishWebhookEvent(
		d.ID,
		"organization.member.role.updated",
		targetMembershipIDuint64,
		"organization_membership",
	)

	if targetMemberShip.UserID == *session.ActiveSignin.UserID {
		handler.RemoveSessionFromCacheAndLocals(c, session.ID)
	}

	database.SyncUserWrapper(database.Connection, targetMemberShip.UserID, "organization.role.removed")

	natsService := service.GetNATS()
	if err := natsService.PublishApiKeyOrgMembershipSync(targetMemberShip.ID); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to enqueue API key permission sync")
	}

	return handler.SendSuccess(c, handler.SuccessResponse{Success: true})
}

func (h *Handler) GetOrganizationMembers(
	c fiber.Ctx,
) error {
	orgID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid organization ID")
	}
	session := handler.GetSession(c)

	if session == nil || session.ActiveSignin == nil || session.ActiveSignin.UserID == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	_, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	d := handler.GetDeployment(c)
	page := fiber.Query[int](c, "page", 1)
	if page < 1 {
		page = 1
	}
	limit := fiber.Query[int](c, "limit", 10)
	if limit < 1 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit
	searchQuery := strings.TrimSpace(c.Query("search"))

	baseWhere := "WHERE search_users.deployment_id = ? AND search_users.organization_ids @> ?::jsonb"
	args := []interface{}{d.ID, fmt.Sprintf("[%d]", orgID)}

	if searchQuery != "" {
		baseWhere += ` AND (
			search_users.search_vector @@ websearch_to_tsquery('english', ?)
			OR search_users.first_name % ?
			OR search_users.last_name % ?
			OR search_users.username % ?
			OR search_users.primary_email % ?
		)`
		args = append(args, searchQuery, searchQuery, searchQuery, searchQuery, searchQuery)
	}

	var userIDs []uint64
	if err := database.Connection.Raw(
		"SELECT user_id FROM search_users "+baseWhere+" ORDER BY created_at DESC LIMIT ? OFFSET ?",
		append(args, limit+1, offset)...,
	).Scan(&userIDs).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to fetch searched members")
	}

	hasMore := false
	if len(userIDs) > limit {
		hasMore = true
		userIDs = userIDs[:limit]
	}

	if len(userIDs) == 0 {
		return handler.SendSuccess(c, MembersListResponse{
			Data: []model.OrganizationMembership{},
			Meta: PaginationMeta{HasMore: false, Page: page, Limit: limit},
		})
	}

	var queryResults []OrganizationMemberQueryResult
	rawSQL := `
		SELECT
			organization_memberships.id,
			organization_memberships.created_at,
			organization_memberships.updated_at,
			organization_memberships.organization_id,
			organization_memberships.user_id,
			json_build_object(
				'id', users.id::text,
				'first_name', users.first_name,
				'last_name', users.last_name,
				'username', users.username,
				'profile_picture_url', users.profile_picture_url,
				'has_profile_picture', users.has_profile_picture,
				'availability', users.availability,
				'public_metadata', COALESCE(users.public_metadata, '{}'),
				'created_at', users.created_at,
				'updated_at', users.updated_at,
				'primary_email_address', CASE
					WHEN primary_email.id IS NOT NULL THEN json_build_object(
						'id', primary_email.id::text,
						'email', primary_email.email_address,
						'is_primary', primary_email.is_primary,
						'verified', primary_email.verified
					)
					ELSE NULL
				END
			) as user_json,
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', organization_roles.id::text,
						'organization_id', CASE WHEN organization_roles.organization_id IS NOT NULL THEN organization_roles.organization_id::text ELSE NULL END,
						'name', organization_roles.name,
						'permissions', organization_roles.permissions,
						'deployment_id', organization_roles.deployment_id::text,
						'created_at', organization_roles.created_at,
						'updated_at', organization_roles.updated_at
					) ORDER BY organization_roles.name
				)
				FROM organization_membership_roles
				JOIN organization_roles ON organization_membership_roles.organization_role_id = organization_roles.id
				WHERE organization_membership_roles.organization_membership_id = organization_memberships.id
				), '[]'::json
			) as roles_json,
			COALESCE(organization_memberships.public_metadata::text, '{}') as public_metadata_json
		FROM organization_memberships
		JOIN users ON organization_memberships.user_id = users.id AND users.deleted_at IS NULL
		LEFT JOIN user_email_addresses primary_email ON users.primary_email_address_id = primary_email.id
		WHERE organization_memberships.organization_id = ?
		AND organization_memberships.user_id = ANY(?)
		AND organization_memberships.deleted_at IS NULL
		ORDER BY organization_memberships.created_at ASC
	`

	if err := database.Connection.Raw(rawSQL, orgID, pq.Array(userIDs)).Scan(&queryResults).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to fetch organization members details")
	}

	memberships := make([]model.OrganizationMembership, len(queryResults))
	for i, result := range queryResults {
		memberships[i] = result.OrganizationMembership

		if result.UserJSON != "" {
			var userData model.PublicUserData
			if err := json.Unmarshal([]byte(result.UserJSON), &userData); err != nil {
				log.Printf("Error parsing user data for member %d: %v", queryResults[i].ID, err)
				log.Printf("UserJSON: %s", result.UserJSON)
			} else {
				memberships[i].User = &userData
			}
		} else {
			log.Printf("No user data JSON for member %d", queryResults[i].ID)
		}

		var roles []*model.OrganizationRole
		if result.RolesJSON != "" && result.RolesJSON != "[]" {
			if err := json.Unmarshal([]byte(result.RolesJSON), &roles); err != nil {
				log.Printf("Error parsing roles for member %d: %v", queryResults[i].ID, err)
				log.Printf("RolesJSON: %s", result.RolesJSON)
			} else {
				memberships[i].Roles = roles
			}
		}

		if result.PublicMetadataJSON != "" && result.PublicMetadataJSON != "{}" && result.PublicMetadataJSON != "null" {
			var metadata datatypes.JSONMap
			if err := json.Unmarshal([]byte(result.PublicMetadataJSON), &metadata); err == nil {
				memberships[i].PublicMetadata = metadata
			} else {
				memberships[i].PublicMetadata = make(datatypes.JSONMap)
			}
		} else {
			memberships[i].PublicMetadata = make(datatypes.JSONMap)
		}
	}

	return handler.SendSuccess(c, MembersListResponse{
		Data: memberships,
		Meta: PaginationMeta{HasMore: hasMore, Page: page, Limit: limit},
	})

}

func (h *Handler) CreateOrganizationRole(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	session := handler.GetSession(c)
	deployment := handler.GetDeployment(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	actingUserMembership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(actingUserMembership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions to manage roles.")
	}

	if !deployment.B2BSettings.CustomOrgRoleEnabled {
		return handler.SendForbidden(c, nil, "Custom organization roles are disabled for this deployment.")
	}

	body, validation := handler.Validate[CreateRoleRequest](c)

	if validation != nil {
		return handler.SendBadRequest(c, validation, "Invalid request")
	}

	for _, permission := range body.Permissions {
		if !slices.Contains(deployment.B2BSettings.OrganizationPermissions, permission) {
			return handler.SendForbidden(c, nil, "Insufficient permissions to manage roles.")
		}
	}

	orgIDValue := getuint64(orgID)
	role := model.OrganizationRole{
		Model:          model.Model{ID: idgen.NextID()},
		OrganizationID: &orgIDValue,
		Name:           body.Name,
		Permissions:    body.Permissions,
		DeploymentID:   deployment.ID,
	}

	if err := database.Connection.Create(&role).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create organization role")
	}

	return handler.SendSuccess(c, role)
}

func (h *Handler) GetOrganizationRoles(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	session := handler.GetSession(c)
	deployment := handler.GetDeployment(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var roles []model.OrganizationRole
	if err := database.Connection.
		Where("deployment_id = ? AND (organization_id = ? OR organization_id IS NULL)", deployment.ID, orgID).
		Find(&roles).
		Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get organization roles")
	}

	return handler.SendSuccess(c, roles)
}

func (h *Handler) RemoveOrganizationRoles(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	roleID := c.Params("roleId")
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	currentMembership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(currentMembership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var role model.OrganizationRole
	if err := database.Connection.
		Where("id = ? AND organization_id = ?", roleID, orgID).
		First(&role).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var membershipIDs []uint64
	if err := database.Connection.
		Table("organization_membership_roles").
		Where("organization_role_id = ?", role.ID).
		Distinct("organization_membership_id").
		Pluck("organization_membership_id", &membershipIDs).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to load role memberships")
	}

	if err := database.Connection.Delete(&role).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization role")
	}

	natsService := service.GetNATS()
	for _, membershipID := range membershipIDs {
		if err := natsService.PublishApiKeyOrgMembershipSync(membershipID); err != nil {
			return handler.SendInternalServerError(c, err, "Failed to enqueue API key permission sync")
		}
	}

	return handler.SendSuccess(c, handler.SuccessResponse{})
}

func (h *Handler) GetOrganizationDomains(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var domains []model.OrganizationDomain
	if err := database.Connection.Where("organization_id = ?", orgID).Find(&domains).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get organization domains")
	}

	return handler.SendSuccess(c, domains)
}

func (h *Handler) AddOrganizationDomain(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	d := handler.GetDeployment(c)

	if !d.B2BSettings.EnterpriseSsoEnabled {
		return handler.SendForbidden(c, nil, "Enterprise SSO is not enabled for this deployment")
	}

	b, validation := handler.Validate[AddDomainRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	requiredPermissions := map[string]bool{
		"organization:admin":  true,
		"organization:manage": true,
	}
	hasPermission := h.service.hasPermission(membership, requiredPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	verificationToken := fmt.Sprintf("wacht-verify-%d", idgen.NextID())

	domain := model.OrganizationDomain{
		ID:                        idgen.NextID(),
		OrganizationID:            getuint64(orgID),
		Fqdn:                      b.Domain,
		DeploymentID:              d.ID,
		Verified:                  false,
		VerificationDnsRecordType: "TXT",
		VerificationDnsRecordName: "_wc-verification",
		VerificationDnsRecordData: verificationToken,
		VerificationAttempts:      0,
	}

	if err := database.Connection.Create(&domain).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to add domain")
	}

	return handler.SendSuccess(c, domain)
}

func (h *Handler) VerifyOrganizationDomain(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	domainID := c.Params("domainId")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	requiredPermissions := map[string]bool{
		"organization:admin":  true,
		"organization:manage": true,
	}
	hasPermission := h.service.hasPermission(membership, requiredPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var domain model.OrganizationDomain
	if err := database.Connection.
		Where("id = ? AND organization_id = ?", getuint64(domainID), getuint64(orgID)).
		First(&domain).
		Error; err != nil {
		return handler.SendNotFound(c, nil, "Domain not found")
	}

	if domain.Verified {
		return handler.SendSuccess(c, OrganizationDomainResponse{Domain: domain})
	}

	domain.VerificationAttempts++
	if err := database.Connection.Save(&domain).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to update domain verification attempts")
	}

	fullRecordName := fmt.Sprintf("%s.%s", domain.VerificationDnsRecordName, domain.Fqdn)

	txtRecords, err := net.LookupTXT(fullRecordName)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify domain. Please ensure you've added the TXT record '%s' with value '%s'",
			fullRecordName, domain.VerificationDnsRecordData)
		return handler.SendBadRequest(c, err, msg)
	}

	verified := slices.Contains(txtRecords, domain.VerificationDnsRecordData)

	if !verified {
		msg := fmt.Sprintf("Verification failed. Please ensure you've added the TXT record '%s' with value '%s'",
			fullRecordName, domain.VerificationDnsRecordData)
		return handler.SendBadRequest(c, nil, msg)
	}

	domain.Verified = true
	if err := database.Connection.Save(&domain).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to verify domain")
	}

	return handler.SendSuccess(c, OrganizationDomainResponse{Domain: domain})
}

func (h *Handler) DeleteOrganizationDomain(
	c fiber.Ctx,
) error {
	orgID := c.Params("id")
	domainID := c.Params("domainId")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	requiredPermissions := map[string]bool{
		"organization:admin":  true,
		"organization:manage": true,
	}
	hasPermission := h.service.hasPermission(membership, requiredPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	if err := database.Connection.
		Delete(&model.OrganizationDomain{OrganizationID: getuint64(orgID), ID: getuint64(domainID)}).
		Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete domain")
	}

	return handler.SendSuccess(c, handler.SuccessResponse{Success: true})
}

func (h *Handler) GetEnterpriseConnections(c fiber.Ctx) error {
	orgID := c.Params("id")
	d := handler.GetDeployment(c)

	if !d.B2BSettings.EnterpriseSsoEnabled {
		return handler.SendForbidden(c, nil, "Enterprise SSO is not enabled for this deployment")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	_, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Not a member of this organization")
	}

	var connections []model.EnterpriseConnection
	if err := database.Connection.
		Where("organization_id = ?", orgID).
		Preload("Domain").
		Find(&connections).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get enterprise connections")
	}

	return handler.SendSuccess(c, connections)
}

func (h *Handler) CreateEnterpriseConnection(c fiber.Ctx) error {
	orgID := c.Params("id")
	d := handler.GetDeployment(c)

	if !d.B2BSettings.EnterpriseSsoEnabled {
		return handler.SendForbidden(c, nil, "Enterprise SSO is not enabled for this deployment")
	}

	b, validation := handler.Validate[CreateEnterpriseConnectionRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	connection := model.EnterpriseConnection{
		ID:             idgen.NextID(),
		OrganizationID: getuint64(orgID),
		DeploymentID:   d.ID,
		Protocol:       b.Protocol,
	}

	if b.DomainID != 0 {
		var domain model.OrganizationDomain
		if err := database.Connection.
			Where("id = ? AND organization_id = ? AND verified = true", b.DomainID, orgID).
			First(&domain).Error; err != nil {
			return handler.SendBadRequest(c, nil, "Domain must be verified before configuring SSO")
		}
		connection.DomainID = &b.DomainID
	}

	switch b.Protocol {
	case "saml":
		connection.IdpEntityID = b.IdpEntityID
		connection.IdpSSOURL = b.IdpSSOURL
		connection.IdpCertificate = b.IdpCertificate
	case "oidc":
		if b.OIDCClientID != "" {
			connection.OIDCClientID = &b.OIDCClientID
		}
		if b.OIDCClientSecret != "" {
			connection.OIDCClientSecret = &b.OIDCClientSecret
		}
		if b.OIDCIssuerURL != "" {
			connection.OIDCIssuerURL = &b.OIDCIssuerURL
		}
		if b.OIDCScopes != "" {
			connection.OIDCScopes = &b.OIDCScopes
		} else {
			defaultScopes := "openid profile email"
			connection.OIDCScopes = &defaultScopes
		}
	}

	if b.JitEnabled != nil {
		connection.JitEnabled = *b.JitEnabled
	} else {
		connection.JitEnabled = true
	}

	if b.AttributeMapping != "" {
		var attrMap map[string]interface{}
		if err := json.Unmarshal([]byte(b.AttributeMapping), &attrMap); err == nil {
			connection.AttributeMapping = attrMap
		}
	}

	if err := database.Connection.Create(&connection).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create enterprise connection")
	}

	return handler.SendSuccess(c, connection)
}

func (h *Handler) UpdateEnterpriseConnection(c fiber.Ctx) error {
	orgID := c.Params("id")
	connectionID := c.Params("connectionId")
	d := handler.GetDeployment(c)

	if !d.B2BSettings.EnterpriseSsoEnabled {
		return handler.SendForbidden(c, nil, "Enterprise SSO is not enabled for this deployment")
	}

	b, validation := handler.Validate[UpdateEnterpriseConnectionRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var connection model.EnterpriseConnection
	if err := database.Connection.
		Where("id = ? AND organization_id = ?", connectionID, orgID).
		First(&connection).Error; err != nil {
		return handler.SendNotFound(c, nil, "Enterprise connection not found")
	}

	if b.DomainID != nil {
		connection.DomainID = b.DomainID
	}
	if b.IdpEntityID != nil {
		connection.IdpEntityID = *b.IdpEntityID
	}
	if b.IdpSSOURL != nil {
		connection.IdpSSOURL = *b.IdpSSOURL
	}
	if b.IdpCertificate != nil {
		connection.IdpCertificate = *b.IdpCertificate
	}

	if b.OIDCClientID != nil {
		connection.OIDCClientID = b.OIDCClientID
	}
	if b.OIDCClientSecret != nil && *b.OIDCClientSecret != "" {
		connection.OIDCClientSecret = b.OIDCClientSecret
	}
	if b.OIDCIssuerURL != nil {
		connection.OIDCIssuerURL = b.OIDCIssuerURL
	}
	if b.OIDCScopes != nil {
		connection.OIDCScopes = b.OIDCScopes
	}
	if b.JitEnabled != nil {
		connection.JitEnabled = *b.JitEnabled
	}
	if b.AttributeMapping != nil && *b.AttributeMapping != "" {
		var attrMap map[string]interface{}
		if err := json.Unmarshal([]byte(*b.AttributeMapping), &attrMap); err == nil {
			connection.AttributeMapping = attrMap
		}
	}

	if err := database.Connection.Save(&connection).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to update enterprise connection")
	}

	return handler.SendSuccess(c, connection)
}

func (h *Handler) DeleteEnterpriseConnection(c fiber.Ctx) error {
	orgID := c.Params("id")
	connectionID := c.Params("connectionId")
	d := handler.GetDeployment(c)

	if !d.B2BSettings.EnterpriseSsoEnabled {
		return handler.SendForbidden(c, nil, "Enterprise SSO is not enabled for this deployment")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	if err := database.Connection.
		Delete(&model.EnterpriseConnection{ID: getuint64(connectionID), OrganizationID: getuint64(orgID)}).
		Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete enterprise connection")
	}

	return handler.SendSuccess(c, handler.SuccessResponse{Success: true})
}

func (h *Handler) TestEnterpriseConnectionConfig(c fiber.Ctx) error {
	d := handler.GetDeployment(c)

	if !d.B2BSettings.EnterpriseSsoEnabled {
		return handler.SendForbidden(c, nil, "Enterprise SSO is not enabled for this deployment")
	}

	b, validation := handler.Validate[TestEnterpriseConnectionRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	result := TestConnectionResult{
		Protocol: b.Protocol,
		Checks:   make(map[string]bool),
		Errors:   make(map[string]string),
	}

	switch b.Protocol {
	case "saml":
		result = validateSAMLConfig(b.IdpCertificate, b.IdpSSOURL, result)
	case "oidc":
		result = validateOIDCConfig(b.OIDCIssuerURL, result)
	}

	// Check if all checks passed
	result.Success = len(result.Errors) == 0
	if result.Success {
		result.Errors = nil
	}

	return handler.SendSuccess(c, result)
}

func (h *Handler) TestEnterpriseConnection(c fiber.Ctx) error {
	orgID := c.Params("id")
	connectionID := c.Params("connectionId")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var connection model.EnterpriseConnection
	if err := database.Connection.
		Where("id = ? AND organization_id = ?", connectionID, orgID).
		First(&connection).Error; err != nil {
		return handler.SendNotFound(c, nil, "Enterprise connection not found")
	}

	result := TestConnectionResult{
		Protocol: connection.Protocol,
		Checks:   make(map[string]bool),
		Errors:   make(map[string]string),
	}

	switch connection.Protocol {
	case "saml":
		result = validateSAMLConfig(connection.IdpCertificate, connection.IdpSSOURL, result)
	case "oidc":
		issuerURL := ""
		if connection.OIDCIssuerURL != nil {
			issuerURL = *connection.OIDCIssuerURL
		}
		result = validateOIDCConfig(issuerURL, result)
	}

	// Check if all checks passed
	result.Success = len(result.Errors) == 0
	if result.Success {
		result.Errors = nil
	}

	return handler.SendSuccess(c, result)
}

func validateSAMLConfig(certificate string, ssoURL string, result TestConnectionResult) TestConnectionResult {
	if certificate != "" {
		certPEM := certificate
		if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
			certPEM = "-----BEGIN CERTIFICATE-----\n" + certPEM + "\n-----END CERTIFICATE-----"
		}

		block, _ := pem.Decode([]byte(certPEM))
		if block != nil {
			_, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				result.Checks["certificate_valid"] = false
				result.Errors["certificate_valid"] = "Invalid X.509 certificate: " + err.Error()
			} else {
				result.Checks["certificate_valid"] = true
			}
		} else {
			result.Checks["certificate_valid"] = false
			result.Errors["certificate_valid"] = "Certificate is not valid PEM format"
		}
	} else {
		result.Checks["certificate_valid"] = false
		result.Errors["certificate_valid"] = "Certificate is required"
	}

	if ssoURL != "" {
		if strings.Contains(ssoURL, "{") || strings.Contains(ssoURL, "}") {
			result.Checks["sso_url_reachable"] = false
			result.Errors["sso_url_reachable"] = "SSO URL contains placeholder values (e.g., {appId}) - please replace with actual values"
			return result
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(ssoURL)
		if err != nil {
			result.Checks["sso_url_reachable"] = false
			result.Errors["sso_url_reachable"] = "SSO URL is not reachable: " + err.Error()
		} else {
			resp.Body.Close()
			result.Checks["sso_url_reachable"] = resp.StatusCode < 500
			if resp.StatusCode >= 500 {
				result.Errors["sso_url_reachable"] = fmt.Sprintf("SSO URL returned server error: %d", resp.StatusCode)
			}
		}
	} else {
		result.Checks["sso_url_reachable"] = false
		result.Errors["sso_url_reachable"] = "SSO URL is required"
	}

	return result
}

func validateOIDCConfig(issuerURL string, result TestConnectionResult) TestConnectionResult {
	if issuerURL == "" {
		result.Checks["issuer_valid"] = false
		result.Errors["issuer_valid"] = "Issuer URL is required"
		return result
	}

	discoveryURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		result.Checks["discovery_reachable"] = false
		result.Errors["discovery_reachable"] = "Failed to fetch OIDC discovery document: " + err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		result.Checks["discovery_reachable"] = false
		result.Errors["discovery_reachable"] = fmt.Sprintf("OIDC discovery returned status %d", resp.StatusCode)
		return result
	}

	result.Checks["discovery_reachable"] = true

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Checks["discovery_valid"] = false
		result.Errors["discovery_valid"] = "Failed to read discovery document"
		return result
	}

	var discovery map[string]interface{}
	if err := json.Unmarshal(body, &discovery); err != nil {
		result.Checks["discovery_valid"] = false
		result.Errors["discovery_valid"] = "Invalid JSON in discovery document"
		return result
	}

	if _, ok := discovery["authorization_endpoint"]; ok {
		result.Checks["authorization_endpoint"] = true
	} else {
		result.Checks["authorization_endpoint"] = false
		result.Errors["authorization_endpoint"] = "Missing authorization_endpoint"
	}

	if _, ok := discovery["token_endpoint"]; ok {
		result.Checks["token_endpoint"] = true
	} else {
		result.Checks["token_endpoint"] = false
		result.Errors["token_endpoint"] = "Missing token_endpoint"
	}

	result.Checks["discovery_valid"] = true

	return result
}

func (h *Handler) GenerateSCIMToken(c fiber.Ctx) error {
	orgID := c.Params("id")
	connectionID := c.Params("connectionId")
	d := handler.GetDeployment(c)

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	connID := getuint64(connectionID)
	orgIDInt := getuint64(orgID)

	var connection model.EnterpriseConnection
	if err := database.Connection.Where("id = ? AND organization_id = ?", connID, orgIDInt).
		First(&connection).Error; err != nil {
		return handler.SendNotFound(c, nil, "Enterprise connection not found")
	}

	scimService := h.service.getSCIMService()
	plainToken, token, err := scimService.GenerateToken(connID, d.ID, orgIDInt)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to generate SCIM token")
	}

	baseURL := fmt.Sprintf("https://%s/scim/v2/%d", d.BackendHost, connID)

	response := SCIMTokenResponse{
		Token:       plainToken,
		TokenPrefix: token.TokenPrefix,
		Enabled:     token.Enabled,
		CreatedAt:   token.CreatedAt.Format(time.RFC3339),
		SCIMBaseURL: baseURL,
	}

	return handler.SendSuccess(c, response)
}

func (h *Handler) GetSCIMToken(c fiber.Ctx) error {
	orgID := c.Params("id")
	connectionID := c.Params("connectionId")
	d := handler.GetDeployment(c)

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	connID := getuint64(connectionID)
	orgIDInt := getuint64(orgID)

	var connection model.EnterpriseConnection
	if err := database.Connection.Where("id = ? AND organization_id = ?", connID, orgIDInt).
		First(&connection).Error; err != nil {
		return handler.SendNotFound(c, nil, "Enterprise connection not found")
	}

	scimService := h.service.getSCIMService()
	token, err := scimService.GetToken(connID)
	if err != nil {
		return handler.SendSuccess(c, GetSCIMTokenResponse{Exists: false, SCIMBaseURL: fmt.Sprintf("https://%s/scim/v2/%d", d.BackendHost, connID)})
	}

	response := SCIMTokenResponse{
		TokenPrefix: token.TokenPrefix,
		Enabled:     token.Enabled,
		CreatedAt:   token.CreatedAt.Format(time.RFC3339),
		SCIMBaseURL: fmt.Sprintf("https://%s/scim/v2/%d", d.BackendHost, connID),
	}

	if token.LastUsedAt != nil {
		response.LastUsedAt = token.LastUsedAt.Format(time.RFC3339)
	}

	return handler.SendSuccess(c, GetSCIMTokenResponse{Exists: true, Token: &response})
}

func (h *Handler) RevokeSCIMToken(c fiber.Ctx) error {
	orgID := c.Params("id")
	connectionID := c.Params("connectionId")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	membership, ok := c.Locals("membership").(model.OrganizationMembership)
	if !ok {
		return handler.SendForbidden(c, nil, "Access denied: Not a member of this organization")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	connID := getuint64(connectionID)
	orgIDInt := getuint64(orgID)

	var connection model.EnterpriseConnection
	if err := database.Connection.Where("id = ? AND organization_id = ?", connID, orgIDInt).
		First(&connection).Error; err != nil {
		return handler.SendNotFound(c, nil, "Enterprise connection not found")
	}

	scimService := h.service.getSCIMService()
	if err := scimService.RevokeToken(connID); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to revoke SCIM token")
	}

	return handler.SendSuccess(c, handler.SuccessResponse{Success: true})
}
