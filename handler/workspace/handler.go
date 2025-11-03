package workspace

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/plugin/dbresolver"
)

func getuint64Param(c *fiber.Ctx, paramName string) (uint64, error) {
	valStr := c.Params(paramName)
	valuint64, err := strconv.ParseUint(valStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid parameter '%s': %w", paramName, err)
	}
	return uint64(valuint64), nil
}

type Handler struct {
	service *WorkspaceService
}

func NewHandler() *Handler {
	return &Handler{
		service: NewWorkspaceService(),
	}
}

func (h *Handler) CreateWorkspace(c *fiber.Ctx) error {
	b, validation := handler.Validate[CreateWorkspaceRequest](c)
	deployment := handler.GetDeployment(c)
	img, _ := c.FormFile("image")
	imgurl := deployment.UISettings.DefaultWorkspaceProfileImageURL
	workspaceid := snowflake.ID()

	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	if img != nil {
		url, err := h.service.uploadWorkspaceImage(workspaceid, img)
		if err != nil {
			log.Println(err)
			return handler.SendInternalServerError(c, err, "Failed to upload workspace image")
		}
		imgurl = url
	}

	var orgMembership model.OrganizationMembership
	if err := database.Connection.Where(
		"organization_id = ? AND user_id = ?",
		b.OrganizationID,
		session.ActiveSignin.UserID,
	).Preload("Roles").First(&orgMembership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Not a member of this organization or insufficient permissions to create a workspace.",
		)
	}

	d := handler.GetDeployment(c)

	workspace := model.Workspace{
		Model: model.Model{
			ID: workspaceid,
		},
		Name:            b.Name,
		Description:     b.Description,
		OrganizationID:  b.OrganizationID,
		ImageUrl:        imgurl,
		PublicMetadata:  datatypes.JSONMap{},
		PrivateMetadata: datatypes.JSONMap{},
		DeploymentID:    deployment.ID,
	}

	txErr := database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&workspace).Error; err != nil {
			return err
		}

		creatorMembership := model.WorkspaceMembership{
			Model: model.Model{
				ID: snowflake.ID(),
			},
			WorkspaceID:              workspace.ID,
			UserID:                   *session.ActiveSignin.UserID,
			OrganizationID:           b.OrganizationID,
			OrganizationMembershipID: orgMembership.ID,
		}
		if err := tx.Create(&creatorMembership).Error; err != nil {
			return err
		}

		if d.B2BSettings.DefaultWorkspaceCreatorRoleID != 0 {
			assoc := model.WorkspaceMembershipRoleAssoc{
				WorkspaceMembershipID: creatorMembership.ID,
				WorkspaceRoleID:       d.B2BSettings.DefaultWorkspaceCreatorRoleID,
				WorkspaceID:           workspace.ID,
				OrganizationID:        workspace.OrganizationID,
			}
			if err := tx.Create(&assoc).Error; err != nil {
				log.Printf("Failed to assign default creator role to workspace %d for user %d: %v", workspace.ID, session.ActiveSignin.UserID, err)
			}
		}
		return nil
	})

	if txErr != nil {
		log.Printf("Failed to create workspace or initial membership: %v", txErr)
		return handler.SendInternalServerError(
			c,
			txErr,
			"Failed to create workspace",
		)
	}

	var finalWorkspace model.Workspace
	if err := database.Connection.
		Preload("Members", "user_id = ?", session.ActiveSignin.UserID).
		Preload("Members.Roles").
		First(&finalWorkspace, workspace.ID).Error; err != nil {
		log.Printf("Failed to fetch created workspace for response: %v", err)
		return handler.SendSuccess(c, fiber.Map{"workspace": workspace})
	}

	utils.PublishWebhookEvent(deployment.ID, "workspace.created", workspace.ID, "workspace")

	return handler.SendSuccess(c, fiber.Map{
		"workspace": finalWorkspace,
	})
}

func (h *Handler) GetWorkspace(c *fiber.Ctx) error {
	workspaceIDStr := c.Params("id")
	workspaceID, err := getuint64Param(c, "id")
	if err != nil {
		return handler.SendBadRequest(c, err, err.Error())
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var workspace model.Workspace
	if err := database.Connection.First(&workspace, workspaceID).Error; err != nil {
		return handler.SendNotFound(c, nil, "Workspace not found")
	}

	// Check if user is a member to allow access
	var membership model.WorkspaceMembership
	if err := database.Connection.Where(
		"workspace_id = ? AND user_id = ?",
		workspaceIDStr, // Use string for direct param match if that's how it was stored
		session.ActiveSignin.UserID,
	).Preload("Roles").First(&membership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Not a member of this workspace",
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"workspace":  workspace,
		"membership": membership,
	})
}

func (h *Handler) GetWorkspaceMembers(c *fiber.Ctx) error {
	workspaceID, err := getuint64Param(c, "id")
	if err != nil {
		return handler.SendBadRequest(c, err, err.Error())
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	// Check current user's membership with raw SQL for better performance
	var actingUserMembershipExists int
	checkSQL := `
		SELECT 1 FROM workspace_memberships
		WHERE workspace_memberships.workspace_id = ?
			AND workspace_memberships.user_id = ?
			AND workspace_memberships.deleted_at IS NULL
		LIMIT 1
	`
	if err := database.Connection.Raw(checkSQL, workspaceID, session.ActiveSignin.UserID).Scan(&actingUserMembershipExists).Error; err != nil || actingUserMembershipExists == 0 {
		return handler.SendForbidden(c, nil, "Insufficient permissions to view members (not a member of the workspace).")
	}

	log.Printf("Fetching workspace members for workspace %d", workspaceID)
	var queryResults []WorkspaceMemberQueryResult
	rawSQL := `
		SELECT
			workspace_memberships.id,
			workspace_memberships.created_at,
			workspace_memberships.updated_at,
			workspace_memberships.workspace_id,
			workspace_memberships.organization_id,
			workspace_memberships.organization_membership_id,
			workspace_memberships.user_id,
			CASE
				WHEN users.id IS NOT NULL THEN json_build_object(
					'id', users.id::text,
					'first_name', users.first_name,
					'last_name', users.last_name,
					'username', users.username,
					'profile_picture_url', users.profile_picture_url,
					'has_profile_picture', users.has_profile_picture,
					'availability', users.availability,
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
				)
				ELSE NULL
			END as public_user_data_json,
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', workspace_roles.id::text,
						'name', workspace_roles.name,
						'permissions', workspace_roles.permissions,
						'organization_id', workspace_roles.organization_id::text,
						'deployment_id', workspace_roles.deployment_id::text,
						'workspace_id', workspace_roles.workspace_id::text,
						'created_at', workspace_roles.created_at,
						'updated_at', workspace_roles.updated_at
					) ORDER BY workspace_roles.name
				)
				FROM workspace_membership_roles
				JOIN workspace_roles ON workspace_membership_roles.workspace_role_id = workspace_roles.id
				WHERE workspace_membership_roles.workspace_membership_id = workspace_memberships.id
				), '[]'::json
			) as roles_json
		FROM workspace_memberships
		LEFT JOIN users ON workspace_memberships.user_id = users.id AND users.deleted_at IS NULL
		LEFT JOIN user_email_addresses primary_email ON users.primary_email_address_id = primary_email.id
		WHERE workspace_memberships.workspace_id = ?
			AND workspace_memberships.deleted_at IS NULL
		ORDER BY workspace_memberships.created_at ASC
	`

	if err := database.Connection.Clauses(dbresolver.Read).Raw(rawSQL, workspaceID).Scan(&queryResults).Error; err != nil {
		log.Printf("Error fetching workspace members for workspace %d: %v", workspaceID, err)
		return handler.SendInternalServerError(c, err, "Failed to get workspace members")
	}

	members := make([]model.WorkspaceMembership, len(queryResults))
	for i, result := range queryResults {
		members[i] = result.WorkspaceMembership

		// Parse user data
		if result.PublicUserDataJSON != "" && result.PublicUserDataJSON != "null" {
			var userData model.PublicUserData
			if err := json.Unmarshal([]byte(result.PublicUserDataJSON), &userData); err != nil {
				log.Printf("Error parsing user data for member %d: %v", members[i].ID, err)
				log.Printf("PublicUserDataJSON: %s", result.PublicUserDataJSON)
			} else {
				members[i].User = userData
			}
		} else {
			log.Printf("No user data JSON for member %d (user_id: %d)", members[i].ID, members[i].UserID)
		}

		// Parse roles
		var roles []*model.WorkspaceRole
		if result.RolesJSON != "" && result.RolesJSON != "[]" {
			if err := json.Unmarshal([]byte(result.RolesJSON), &roles); err == nil {
				members[i].Roles = roles
			}
		}
	}

	return handler.SendSuccess(c, members)
}

func (h *Handler) GetWorkspaceRoles(c *fiber.Ctx) error {
	workspaceID, err := getuint64Param(c, "id")
	if err != nil {
		return handler.SendBadRequest(c, err, err.Error())
	}
	d := handler.GetDeployment(c)
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var actingUserMembership model.WorkspaceMembership
	if err := database.Connection.
		Where("workspace_id = ? AND user_id = ?", workspaceID, session.ActiveSignin.UserID).
		First(&actingUserMembership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions to view roles (not a member of the workspace).")
	}

	var roles []model.WorkspaceRole
	if err := database.Connection.
		Where("deployment_id = ? AND (workspace_id = ? OR workspace_id IS NULL)", d.ID, workspaceID).
		Find(&roles).Error; err != nil {
		log.Printf("Error fetching workspace roles for workspace %d: %v", workspaceID, err)
		return handler.SendInternalServerError(c, err, "Failed to get workspace roles")
	}
	return handler.SendSuccess(c, roles)
}

func (h *Handler) CreateWorkspaceRole(c *fiber.Ctx) error {
	workspaceID, err := getuint64Param(c, "id")
	if err != nil {
		return handler.SendBadRequest(c, err, err.Error())
	}

	d := handler.GetDeployment(c)
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign-in")
	}

	// Check workspace membership
	var membership model.WorkspaceMembership
	if err := database.Connection.
		Where("workspace_id = ? AND user_id = ?", workspaceID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions (not a member of the workspace).")
	}

	// Check if user has permission to manage workspace
	hasPermission := false
	for _, role := range membership.Roles {
		for _, perm := range role.Permissions {
			if perm == "workspace:owner" || perm == "workspace:admin" || perm == "workspace:manage" {
				hasPermission = true
				break
			}
		}
		if hasPermission {
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions to manage workspace roles.")
	}

	// Validate request body
	var body struct {
		Name        string   `json:"name" validate:"required,min=2,max=100"`
		Permissions []string `json:"permissions"`
	}

	if err := c.BodyParser(&body); err != nil {
		return handler.SendBadRequest(c, err, "Invalid request body")
	}

	// Create the role
	role := model.WorkspaceRole{
		Model:          model.Model{ID: snowflake.ID()},
		DeploymentID:   d.ID,
		WorkspaceID:    workspaceID,
		OrganizationID: membership.OrganizationID,
		Name:           body.Name,
		Permissions:    body.Permissions,
	}

	if err := database.Connection.Create(&role).Error; err != nil {
		log.Printf("Failed to create workspace role: %v", err)
		return handler.SendInternalServerError(c, err, "Failed to create workspace role")
	}

	return handler.SendSuccess(c, role)
}

func (h *Handler) DeleteWorkspaceRole(c *fiber.Ctx) error {
	workspaceID, err := getuint64Param(c, "id")
	if err != nil {
		return handler.SendBadRequest(c, err, err.Error())
	}

	roleID, err := getuint64Param(c, "roleId")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid role ID")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign-in")
	}

	var membership model.WorkspaceMembership
	if err := database.Connection.
		Where("workspace_id = ? AND user_id = ?", workspaceID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions (not a member of the workspace).")
	}

	hasPermission := false
	for _, role := range membership.Roles {
		for _, perm := range role.Permissions {
			if perm == "workspace:owner" || perm == "workspace:admin" || perm == "workspace:manage" {
				hasPermission = true
				break
			}
		}
		if hasPermission {
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions to manage workspace roles.")
	}

	var roleToDelete model.WorkspaceRole
	if err := database.Connection.
		Where("id = ? AND workspace_id = ?", roleID, workspaceID).
		First(&roleToDelete).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return handler.SendNotFound(c, nil, "Role not found")
		}
		return handler.SendInternalServerError(c, err, "Failed to find role")
	}

	var memberCount int64
	database.Connection.Model(&model.WorkspaceMembershipRoleAssoc{}).
		Where("workspace_role_id = ?", roleID).
		Count(&memberCount)

	if memberCount > 0 {
		return handler.SendBadRequest(c, nil, fmt.Sprintf("Cannot delete role - %d members still have this role assigned", memberCount))
	}

	if err := database.Connection.Delete(&roleToDelete).Error; err != nil {
		log.Printf("Failed to delete workspace role %d: %v", roleID, err)
		return handler.SendInternalServerError(c, err, "Failed to delete role")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message": "Role deleted successfully",
	})
}

func (h *Handler) AddWorkspaceMemberRole(c *fiber.Ctx) error {
	workspaceID, err := getuint64Param(c, "workspaceId")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid workspace ID: "+err.Error())
	}
	targetMembershipID, err := getuint64Param(c, "membershipId")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid membership ID: "+err.Error())
	}
	roleIDToAdd, err := getuint64Param(c, "roleId")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid role ID: "+err.Error())
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var actingUserMembership model.WorkspaceMembership
	if err := database.Connection.
		Where("workspace_id = ? AND user_id = ?", workspaceID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&actingUserMembership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Permission check failed: not a member of the workspace.")
	}

	if !h.service.hasWorkspacePermission(actingUserMembership, workspaceManagementPermissions) {
		return handler.SendForbidden(c, nil, "Insufficient permissions to manage workspace roles.")
	}

	var role model.WorkspaceRole
	if err := database.Connection.First(&role, roleIDToAdd).Error; err != nil {
		return handler.SendNotFound(c, nil, "Role not found.")
	}

	var targetMembership model.WorkspaceMembership
	if err := database.Connection.
		Where("id = ? AND workspace_id = ?", targetMembershipID, workspaceID).
		First(&targetMembership).Error; err != nil {
		return handler.SendNotFound(c, nil, "Target workspace membership not found.")
	}

	assoc := model.WorkspaceMembershipRoleAssoc{
		WorkspaceMembershipID: targetMembershipID,
		WorkspaceRoleID:       roleIDToAdd,
		WorkspaceID:           workspaceID,                     // Populate from context/targetMembership
		OrganizationID:        targetMembership.OrganizationID, // Populate from targetMembership
	}

	var existingAssocCount int64
	database.Connection.Model(&model.WorkspaceMembershipRoleAssoc{}).
		Where("workspace_membership_id = ? AND workspace_role_id = ?", targetMembershipID, roleIDToAdd).
		Count(&existingAssocCount)
	if existingAssocCount > 0 {
		return handler.SendBadRequest(c, nil, "Role already assigned to this member.")
	}

	if err := database.Connection.Create(&assoc).Error; err != nil {
		log.Printf("Failed to add role %d to workspace membership %d: %v", roleIDToAdd, targetMembershipID, err)
		return handler.SendInternalServerError(c, err, "Failed to add role to member.")
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "workspace.member.role.updated", targetMembershipID, "workspace_membership")

	return handler.SendSuccess(c, fiber.Map{"success": true})
}

func (h *Handler) RemoveWorkspaceMemberRole(c *fiber.Ctx) error {
	workspaceID, err := getuint64Param(c, "workspaceId")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid workspace ID: "+err.Error())
	}
	targetMembershipID, err := getuint64Param(c, "membershipId")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid membership ID: "+err.Error())
	}
	roleIDToRemove, err := getuint64Param(c, "roleId")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid role ID: "+err.Error())
	}

	session := handler.GetSession(c)
	d := handler.GetDeployment(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var actingUserMembership model.WorkspaceMembership
	if err := database.Connection.
		Where("workspace_id = ? AND user_id = ?", workspaceID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&actingUserMembership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Permission check failed: not a member of the workspace.")
	}

	if !h.service.hasWorkspacePermission(actingUserMembership, workspaceManagementPermissions) {
		return handler.SendForbidden(c, nil, "Insufficient permissions to manage workspace roles.")
	}

	var targetMembership model.WorkspaceMembership
	if err := database.Connection.
		Where("id = ? AND workspace_id = ?", targetMembershipID, workspaceID).
		First(&targetMembership).Error; err != nil {
		return handler.SendNotFound(c, nil, "Target workspace membership not found.")
	}

	isDefaultOwnerRole := (roleIDToRemove == d.B2BSettings.DefaultWorkspaceCreatorRoleID)
	isSelfRemoval := (targetMembership.UserID == *session.ActiveSignin.UserID)

	if isDefaultOwnerRole && isSelfRemoval {
		var otherOwnerCount int64
		if errCount := database.Connection.Table("workspace_membership_roles").
			Where("workspace_id = ? AND workspace_role_id = ? AND workspace_membership_id != ?",
				workspaceID,
				d.B2BSettings.DefaultWorkspaceCreatorRoleID,
				targetMembershipID).
			Count(&otherOwnerCount).Error; errCount != nil {
			log.Printf("Error counting other workspace owners for workspace %d: %v", workspaceID, errCount)
			return handler.SendInternalServerError(c, errCount, "Failed to verify workspace owner status.")
		}
		if otherOwnerCount == 0 {
			return handler.SendForbidden(c, nil, "Cannot remove your own owner role as you are the sole owner in this workspace. Please assign this role to another member first.")
		}
	}

	result := database.Connection.
		Where("workspace_membership_id = ? AND workspace_role_id = ?", targetMembershipID, roleIDToRemove).
		Delete(&model.WorkspaceMembershipRoleAssoc{})

	if result.Error != nil {
		log.Printf("Error removing role %d from workspace membership %d: %v", roleIDToRemove, targetMembershipID, result.Error)
		return handler.SendInternalServerError(c, result.Error, "Failed to remove role from member.")
	}
	if result.RowsAffected == 0 {
		return handler.SendNotFound(c, nil, "Role association not found or already removed.")
	}

	utils.PublishWebhookEvent(d.ID, "workspace.member.role.updated", targetMembershipID, "workspace_membership")

	return handler.SendSuccess(c, fiber.Map{"success": true})
}

func (h *Handler) UpdateWorkspace(c *fiber.Ctx) error {
	workspaceID, err := getuint64Param(c, "id")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid workspace ID: "+err.Error())
	}

	b, validation := handler.Validate[UpdateWorkspaceRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var workspace model.Workspace
	if err := database.Connection.First(&workspace, workspaceID).Error; err != nil {
		return handler.SendNotFound(c, nil, "Workspace not found")
	}

	var actingUserMembership model.WorkspaceMembership
	if err := database.Connection.Where("workspace_id = ? AND user_id = ?",
		workspaceID,
		session.ActiveSignin.UserID,
	).
		Preload("Roles").
		Preload("OrganizationMembership").
		Preload("OrganizationMembership.Roles").
		First(&actingUserMembership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Permission check failed: not a member of the workspace.",
		)
	}

	if !h.service.hasWorkspacePermission(actingUserMembership, workspaceAdminPermissions) {
		return handler.SendForbidden(
			c,
			nil,
			"Insufficient permissions to update workspace settings.",
		)
	}

	if b.Name != "" {
		workspace.Name = b.Name
	}
	if b.Description != "" {
		workspace.Description = b.Description
	}

	if err := database.Connection.Save(&workspace).Error; err != nil {
		log.Printf("Failed to update workspace %d: %v", workspaceID, err)
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to update workspace",
		)
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "workspace.updated", workspace.ID, "workspace")

	return handler.SendSuccess(c, fiber.Map{
		"workspace": workspace,
	})
}

func (h *Handler) DeleteWorkspace(c *fiber.Ctx) error {
	workspaceID, err := getuint64Param(c, "id")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid workspace ID: "+err.Error())
	}
	session := handler.GetSession(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var actingUserMembership model.WorkspaceMembership
	if err := database.Connection.Where(
		"workspace_id = ? AND user_id = ?",
		workspaceID,
		session.ActiveSignin.UserID,
	).
		Preload("Roles").First(&actingUserMembership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Permission check failed: Not a member or workspace does not exist.",
		)
	}

	if !h.service.hasWorkspacePermission(actingUserMembership, workspaceDeletePermissions) {
		return handler.SendForbidden(
			c,
			nil,
			"Only workspace owners can delete the workspace.",
		)
	}

	var orgUsingThisAsAutoAssign model.Organization
	if err := database.Connection.Where("auto_assigned_workspace_id = ?", workspaceID).First(&orgUsingThisAsAutoAssign).Error; err == nil {
		return handler.SendForbidden(c, nil, fmt.Sprintf("Cannot delete workspace as it is configured as the auto-assigned workspace for organization '%s'. Please change that organization's settings first.", orgUsingThisAsAutoAssign.Name))
	} else if err != gorm.ErrRecordNotFound {
		log.Printf("Error checking if workspace %d is an auto-assigned workspace: %v", workspaceID, err)
		return handler.SendInternalServerError(c, err, "Failed to verify workspace status before deletion.")
	}

	if err := database.Connection.Where("workspace_id = ?", workspaceID).Delete(&model.WorkspaceMembershipRoleAssoc{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization")
	}

	if err := database.Connection.Where("workspace_id = ?", workspaceID).Delete(&model.WorkspaceMembership{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete workspace memberships")
	}

	if err := database.Connection.Where("workspace_id = ?", workspaceID).Delete(&model.WorkspaceRole{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete workspace roles")
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "workspace.deleted", workspaceID, "workspace")

	if err := database.Connection.Delete(&model.Workspace{}, workspaceID).Error; err != nil {
		log.Printf("Failed to delete workspace %d: %v", workspaceID, err)
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to delete workspace",
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}

func (h *Handler) InviteMember(c *fiber.Ctx) error {
	workspaceID, err := getuint64Param(c, "id")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid workspace ID: "+err.Error())
	}

	type AddMemberToWorkspaceRequest struct {
		Email  string `json:"email" validate:"required,email"`
		RoleID uint64 `json:"role_id" validate:"required"` // WorkspaceRoleID
	}

	b, validation := handler.Validate[AddMemberToWorkspaceRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var actingUserMembership model.WorkspaceMembership
	if err := database.Connection.
		Where("workspace_id = ? AND user_id = ?", workspaceID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&actingUserMembership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Permission check failed: not a member of the workspace.")
	}
	if !h.service.hasWorkspacePermission(actingUserMembership, workspaceManagementPermissions) {
		return handler.SendForbidden(c, nil, "Insufficient permissions to add members to this workspace.")
	}

	var userToInvite model.User
	if err := database.Connection.Joins("PrimaryEmailAddress").Where(`"user_email_addresses"."email" = ?`, b.Email).First(&userToInvite).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return handler.SendNotFound(c, nil, "User with the specified email not found.")
		}
		log.Printf("Error finding user by email %s: %v", b.Email, err)
		return handler.SendInternalServerError(c, err, "Error finding user.")
	}

	var roleToAssign model.WorkspaceRole
	if err := database.Connection.First(&roleToAssign, b.RoleID).Error; err != nil {
		return handler.SendNotFound(c, nil, "Specified role not found.")
	}

	var existingMembership model.WorkspaceMembership
	if err := database.Connection.
		Where("workspace_id = ? AND user_id = ?", workspaceID, userToInvite.ID).
		First(&existingMembership).Error; err == nil {
		return handler.SendBadRequest(c, nil, "User is already a member of this workspace.")
	} else if err != gorm.ErrRecordNotFound {
		log.Printf("Error checking existing workspace membership for user %d in workspace %d: %v", userToInvite.ID, workspaceID, err)
		return handler.SendInternalServerError(c, err, "Error checking existing membership.")
	}

	var targetUserOrgMembership model.OrganizationMembership
	var workspaceForOrgID model.Workspace
	if err := database.Connection.Select("organization_id").First(&workspaceForOrgID, workspaceID).Error; err != nil {
		log.Printf("Failed to get workspace org_id %d: %v", workspaceID, err)
		return handler.SendInternalServerError(c, err, "Failed to determine workspace organization.")
	}

	if err := database.Connection.Where("organization_id = ? AND user_id = ?", workspaceForOrgID.OrganizationID, userToInvite.ID).First(&targetUserOrgMembership).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return handler.SendBadRequest(c, nil, "User to be added is not a member of the workspace's organization.")
		}
		log.Printf("Error fetching organization membership for user %d in org %d: %v", userToInvite.ID, workspaceForOrgID.OrganizationID, err)
		return handler.SendInternalServerError(c, err, "Error verifying user's organization membership.")
	}

	newWorkspaceMembership := model.WorkspaceMembership{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		WorkspaceID:              workspaceID,
		UserID:                   userToInvite.ID,
		OrganizationID:           workspaceForOrgID.OrganizationID,
		OrganizationMembershipID: targetUserOrgMembership.ID,
	}

	txErr := database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&newWorkspaceMembership).Error; err != nil {
			return err
		}
		assoc := model.WorkspaceMembershipRoleAssoc{
			WorkspaceMembershipID: newWorkspaceMembership.ID,
			WorkspaceRoleID:       b.RoleID,
			WorkspaceID:           workspaceID,
			OrganizationID:        newWorkspaceMembership.OrganizationID,
		}
		if err := tx.Create(&assoc).Error; err != nil {
			return err
		}
		return nil
	})

	if txErr != nil {
		log.Printf("Failed to add member or assign role to workspace %d: %v", workspaceID, txErr)
		return handler.SendInternalServerError(c, txErr, "Failed to add member to workspace.")
	}

	database.Connection.Preload("User").Preload("Roles").First(&newWorkspaceMembership, newWorkspaceMembership.ID)

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "workspace.member.added", newWorkspaceMembership.ID, "workspace_membership")

	return handler.SendSuccess(c, fiber.Map{"membership": newWorkspaceMembership})
}

func (h *Handler) RemoveMember(c *fiber.Ctx) error {
	workspaceID, err := getuint64Param(c, "id")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid workspace ID: "+err.Error())
	}

	targetUserID, err := getuint64Param(c, "memberId")
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid member ID: "+err.Error())
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var actingUserMembership model.WorkspaceMembership
	if err := database.Connection.
		Where("workspace_id = ? AND user_id = ?", workspaceID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&actingUserMembership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Permission check failed: not a member of the workspace.")
	}

	if !h.service.hasWorkspacePermission(actingUserMembership, workspaceManagementPermissions) {
		return handler.SendForbidden(c, nil, "Insufficient permissions to remove members from this workspace.")
	}

	var targetMembership model.WorkspaceMembership
	if err := database.Connection.
		Where("workspace_id = ? AND user_id = ?", workspaceID, targetUserID).
		First(&targetMembership).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return handler.SendNotFound(c, nil, "Member not found in this workspace.")
		}
		log.Printf("Error finding membership for user %d in workspace %d: %v", targetUserID, workspaceID, err)
		return handler.SendInternalServerError(c, err, "Error finding member to remove.")
	}

	d := handler.GetDeployment(c)
	var isTargetLastOwner bool = false
	var ownerRoleCountForTarget int64
	database.Connection.Model(&model.WorkspaceMembershipRoleAssoc{}).
		Where("workspace_membership_id = ? AND workspace_role_id = ?", targetMembership.ID, d.B2BSettings.DefaultWorkspaceCreatorRoleID).
		Count(&ownerRoleCountForTarget)

	if ownerRoleCountForTarget > 0 { // Target user has the owner role
		var totalOwnerCountInWorkspace int64
		database.Connection.Table("workspace_membership_roles").
			Where("workspace_id = ? AND workspace_role_id = ?", workspaceID, d.B2BSettings.DefaultWorkspaceCreatorRoleID).
			Count(&totalOwnerCountInWorkspace)
		if totalOwnerCountInWorkspace <= 1 {
			isTargetLastOwner = true
		}
	}

	if isTargetLastOwner && targetMembership.UserID != *session.ActiveSignin.UserID {
		return handler.SendForbidden(c, nil, "Cannot remove this member as they are the sole owner. Assign ownership to another member first or delete the workspace.")
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "workspace.member.removed", targetMembership.ID, "workspace_membership")

	txErr := database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("workspace_membership_id = ?", targetMembership.ID).Delete(&model.WorkspaceMembershipRoleAssoc{}).Error; err != nil {
			return err
		}
		if err := tx.Delete(&targetMembership).Error; err != nil {
			return err
		}
		return nil
	})

	if txErr != nil {
		log.Printf("Failed to remove member (User ID: %d, Membership ID: %d) from workspace %d: %v", targetUserID, targetMembership.ID, workspaceID, txErr)
		return handler.SendInternalServerError(
			c,
			txErr,
			"Failed to remove member",
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}
