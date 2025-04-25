package organization

import (
	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/gorm"
)

type Handler struct {
	service *OrgService
}

func NewHandler() *Handler {
	return &Handler{
		service: NewOrgService(),
	}
}

func (h *Handler) CreateOrganization(c *fiber.Ctx) error {
	b, verr := handler.Validate[CreateOrgRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	org := model.Organization{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		Name: b.Name,
	}

	membership := model.OrganizationMembership{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		OrganizationID: org.ID,
		UserID:         session.ActiveSignin.UserID,
		Role:           []*model.DeploymentOrganizationRole{},
	}

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&org).Error; err != nil {
			return err
		}
		if err := tx.Create(&membership).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to create organization",
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"organization": org,
		"membership":   membership,
	})
}

func (h *Handler) GetOrganization(c *fiber.Ctx) error {
	orgID := c.Params("id")
	session := handler.GetSession(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var org model.Organization
	if err := database.Connection.First(&org, orgID).Error; err != nil {
		return handler.SendNotFound(c, nil, "Organization not found")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.Where(
		"organization_id = ? AND user_id = ?",
		orgID,
		session.ActiveSignin.UserID,
	).Preload("Role").First(&membership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Not a member of this organization",
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"organization": org,
		"membership":   membership,
	})
}

func (h *Handler) UpdateOrganization(c *fiber.Ctx) error {
	orgID := c.Params("id")
	b, verr := handler.Validate[UpdateOrgRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var org model.Organization
	if err := database.Connection.First(&org, orgID).Error; err != nil {
		return handler.SendNotFound(c, nil, "Organization not found")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).Preload("Role").First(&membership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Insufficient permissions",
		)
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" {
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

	org.Name = b.Name
	if err := database.Connection.Save(&org).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to update organization",
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"organization": org,
	})
}

func (h *Handler) DeleteOrganization(c *fiber.Ctx) error {
	orgID := c.Params("id")
	session := handler.GetSession(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).Preload("Role").First(&membership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Only organization owner can delete the organization",
		)
	}

	isOwner := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" {
			isOwner = true
			break
		}
	}

	if !isOwner {
		return handler.SendForbidden(
			c,
			nil,
			"Only organization owner can delete the organization",
		)
	}

	if err := database.Connection.Delete(&model.Organization{}, orgID).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to delete organization",
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}

func (h *Handler) InviteMember(c *fiber.Ctx) error {
	orgID := c.Params("id")
	b, verr := handler.Validate[InviteMemberRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).Preload("Role").First(&membership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Insufficient permissions",
		)
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" {
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

	var existingMembership model.OrganizationMembership
	if err := database.Connection.Where(
		"organization_id = ? AND user_id = ?",
		orgID,
		userEmail.UserID,
	).First(&existingMembership).Error; err == nil {
		return handler.SendBadRequest(
			c,
			nil,
			"User is already a member",
		)
	}

	newMembership := model.OrganizationMembership{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		OrganizationID: uint(snowflake.ID()),
		UserID:         userEmail.UserID,
		Role:           []*model.DeploymentOrganizationRole{},
	}

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
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
	orgID := c.Params("id")
	memberID := c.Params("memberId")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).Preload("Role").First(&membership).Error; err != nil {
		return handler.SendForbidden(
			c,
			nil,
			"Insufficient permissions",
		)
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" {
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

	if err := database.Connection.Where("organization_id = ? AND user_id = ?", orgID, memberID).Delete(&model.OrganizationMembership{}).Error; err != nil {
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
