package workspace

import (
	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/gorm"
)

type Handler struct {
	service *WorkspaceService
}

func NewHandler() *Handler {
	return &Handler{
		service: NewWorkspaceService(),
	}
}

func (h *Handler) CreateWorkspace(c *fiber.Ctx) error {
	b, verr := handler.Validate[CreateWorkspaceRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var orgMembership model.OrganizationMembership
	if err := database.Connection.Where(
		"organization_id = ? AND user_id = ?",
		b.OrganizationID,
		session.ActiveSignin.UserID,
	).First(&orgMembership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Not a member of this organization",
		)
	}

	workspace := model.Workspace{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		Name:        b.Name,
		Description: b.Description,
	}

	// ownerRole := &model.WorkspaceRole{
	// 	Model: model.Model{
	// 		ID: uint(snowflake.ID()),
	// 	},
	// 	Name: "workspace:owner",
	// 	Permissions: []*model.WorkspaceRolePermissions{
	// 		{
	// 			Model: model.Model{
	// 				ID: uint(snowflake.ID()),
	// 			},
	// 			Permission: "all",
	// 		},
	// 	},
	// }

	// memberRole := &model.WorkspaceRole{
	// 	Model: model.Model{
	// 		ID: uint(snowflake.ID()),
	// 	},
	// 	Name: "workspace:member",
	// 	Permissions: []*model.WorkspaceRolePermissions{
	// 		{
	// 			Model: model.Model{
	// 				ID: uint(snowflake.ID()),
	// 			},
	// 			Permission: "read",
	// 		},
	// 	},
	// }

	membership := model.WorkspaceMembership{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		WorkspaceID: workspace.ID,
		UserID:      session.ActiveSignin.UserID,
		// Role:        []*model.WorkspaceRole{ownerRole},
	}

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&workspace).Error; err != nil {
			return err
		}
		// if err := tx.Create(&ownerRole).Error; err != nil {
		// 	return err
		// }
		// if err := tx.Create(&memberRole).Error; err != nil {
		// 	return err
		// }
		if err := tx.Create(&membership).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to create workspace",
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"workspace":  workspace,
		"membership": membership,
	})
}

func (h *Handler) GetWorkspace(c *fiber.Ctx) error {
	workspaceID := c.Params("id")
	session := handler.GetSession(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var workspace model.Workspace
	if err := database.Connection.First(&workspace, workspaceID).Error; err != nil {
		return handler.SendNotFound(c, nil, "Workspace not found")
	}

	var membership model.WorkspaceMembership
	if err := database.Connection.Where(
		"workspace_id = ? AND user_id = ?",
		workspaceID,
		session.ActiveSignin.UserID,
	).Preload("Role").First(&membership).Error; err != nil {
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

func (h *Handler) UpdateWorkspace(c *fiber.Ctx) error {
	workspaceID := c.Params("id")
	b, verr := handler.Validate[UpdateWorkspaceRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var workspace model.Workspace
	if err := database.Connection.First(&workspace, workspaceID).Error; err != nil {
		return handler.SendNotFound(c, nil, "Workspace not found")
	}

	var membership model.WorkspaceMembership
	if err := database.Connection.Where("workspace_id = ? AND user_id = ?",
		workspaceID,
		session.ActiveSignin.UserID,
	).
		Preload("Role").First(&membership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Insufficient permissions",
		)
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "workspace:owner" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(
			c,
			nil,
			"Insufficient permissions",
		)
	}

	workspace.Name = b.Name
	workspace.Description = b.Description

	if err := database.Connection.Save(&workspace).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to update workspace",
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"workspace": workspace,
	})
}

func (h *Handler) DeleteWorkspace(c *fiber.Ctx) error {
	workspaceID := c.Params("id")
	session := handler.GetSession(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.WorkspaceMembership
	if err := database.Connection.Where(
		"workspace_id = ? AND user_id = ?",
		workspaceID,
		session.ActiveSignin.UserID,
	).
		Preload("Role").First(&membership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Only workspace owner can delete the workspace",
		)
	}

	isOwner := false
	for _, role := range membership.Role {
		if role.Name == "workspace:owner" {
			isOwner = true
			break
		}
	}

	if !isOwner {
		return handler.SendForbidden(
			c,
			nil,
			"Only workspace owner can delete the workspace",
		)
	}

	if err := database.Connection.Delete(&model.Workspace{}, workspaceID).Error; err != nil {
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
	workspaceID := c.Params("id")
	b, verr := handler.Validate[InviteWorkspaceMemberRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.WorkspaceMembership
	if err := database.Connection.Where("workspace_id = ? AND user_id = ?", workspaceID, session.ActiveSignin.UserID).Preload("Role").First(&membership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Insufficient permissions",
		)
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "workspace:owner" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(
			c,
			nil,
			"Insufficient permissions",
		)
	}

	var userEmail model.UserEmailAddress
	if err := database.Connection.Where("email = ?", b.Email).First(&userEmail).Error; err != nil {
		return handler.SendNotFound(c, nil, "User not found")
	}

	var existingMembership model.WorkspaceMembership
	if err := database.Connection.Where(
		"workspace_id = ? AND user_id = ?",
		workspaceID,
		userEmail.UserID,
	).First(&existingMembership).Error; err == nil {
		return handler.SendBadRequest(
			c,
			nil,
			"User is already a member",
		)
	}

	// role := &model.WorkspaceRole{
	// 	Model: model.Model{
	// 		ID: uint(snowflake.ID()),
	// 	},
	// 	Name: "workspace:" + b.Role,
	// }

	// switch b.Role {
	// case "owner":
	// 	role.Permissions = []*model.WorkspaceRolePermissions{{
	// 		Model:      model.Model{ID: uint(snowflake.ID())},
	// 		Permission: "all",
	// 	}}
	// case "member":
	// 	role.Permissions = []*model.WorkspaceRolePermissions{{
	// 		Model:      model.Model{ID: uint(snowflake.ID())},
	// 		Permission: "read",
	// 	}}
	// }

	newMembership := model.WorkspaceMembership{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		WorkspaceID: uint(snowflake.ID()),
		UserID:      userEmail.UserID,
		// Role:        []*model.WorkspaceRole{role},
	}

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		// if err := tx.Create(&role).Error; err != nil {
		// 	return err
		// }
		if err := tx.Create(&newMembership).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to add member",
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"membership": newMembership,
	})
}

func (h *Handler) RemoveMember(c *fiber.Ctx) error {
	workspaceID := c.Params("id")
	memberID := c.Params("memberId")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.WorkspaceMembership
	if err := database.Connection.Where("workspace_id = ? AND user_id = ?", workspaceID, session.ActiveSignin.UserID).Preload("Role").First(&membership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Insufficient permissions",
		)
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "workspace:owner" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(
			c,
			nil,
			"Insufficient permissions",
		)
	}

	if err := database.Connection.Where("workspace_id = ? AND user_id = ?", workspaceID, memberID).Delete(&model.WorkspaceMembership{}).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to remove member",
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}
