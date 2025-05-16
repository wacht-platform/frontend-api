package organization

import (
	"fmt"
	"log"
	"net"
	"slices"
	"strconv"

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

func getuint64(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		panic("invalid organization id")
	}
	return uint64(v)
}

func (h *Handler) CreateOrganization(
	c *fiber.Ctx,
) error {
	d := handler.GetDeployment(c)
	b, validation := handler.Validate[CreateOrgRequest](c)
	img, _ := c.FormFile("image")
	imgurl := d.UISettings.DefaultOrganizationProfileImageURL
	orgid := snowflake.ID()

	if !d.B2BSettings.OrganizationsEnabled {
		return handler.SendBadRequest(c, nil, "Organizations are not enabled for this deployment")
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

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
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
			ID: snowflake.ID(),
		},
		OrganizationID: orgid,
		UserID:         session.ActiveSignin.UserID,
	}

	err := database.Connection.Transaction(
		func(tx *gorm.DB) error {
			if err := tx.Create(&org).Error; err != nil {
				return err
			}
			if err := tx.Create(&membership).Error; err != nil {
				return err
			}
			if err := tx.Exec(
				fmt.Sprintf(
					"INSERT INTO %s (organization_membership_id, organization_role_id, organization_id) VALUES (?, ?, ?)",
					"organization_membership_roles",
				),
				membership.ID,
				d.B2BSettings.DefaultOrgCreatorRoleID,
				org.ID,
			).Error; err != nil {
				return err
			}
			session.ActiveSignin.ActiveOrganizationMembershipID = &membership.ID
			database.Connection.Save(session.ActiveSignin)
			return nil
		},
	)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create organization")
	}

	return handler.SendSuccess(c, fiber.Map{
		"organization": org,
		"membership":   membership,
	})
}

func (h *Handler) LeaveOrganization(
	c *fiber.Ctx,
) error {
	orgIDStr := c.Params("id")
	orgID := getuint64(orgIDStr)
	session := handler.GetSession(c)
	d := handler.GetDeployment(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).
		Error; err != nil {
		log.Println("Error fetching membership:", err)
		return handler.SendInternalServerError(c, err, "Failed to retrieve membership details")
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
			log.Println("Error counting other admins using DefaultOrgCreatorRoleID on organization_membership_roles:", err)
			return handler.SendInternalServerError(c, err, "Failed to verify organization admin status")
		}

		if adminCount == 0 {
			return handler.SendForbidden(c, nil, "Cannot leave organization as the sole admin. Please transfer ownership or assign this role to another member first.")
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
				if errDb := database.Connection.Save(session.ActiveSignin).Error; errDb != nil {
					log.Printf("Failed to clear active organization ID for user %d: %v", session.ActiveSignin.UserID, errDb)
				}
			}

			return nil
		},
	)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to leave organization")
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}

func (h *Handler) UpdateOrganization(
	c *fiber.Ctx,
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

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		Joins("Organization").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	img, _ := c.FormFile("image")

	org := membership.Organization

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
		org.AutoAssignedWorkspaceID = b.AutoAssignedWorkspaceID
	}

	if img != nil {
		url, err := h.service.uploadOrganizationImage(getuint64(orgID), img)
		if err != nil {
			log.Println(err)
			return handler.SendInternalServerError(c, err, "Failed to upload organization image")
		}

		org.ImageUrl = url
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

	return handler.SendSuccess(c, org)
}

func (h *Handler) DeleteOrganization(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	session := handler.GetSession(
		c,
	)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Only organization owner can delete the organization")
	}

	hasPermission := h.service.hasPermission(membership, orgOwnerPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Only organization owner can delete the organization")
	}

	if err := database.Connection.Delete(&model.Organization{}, orgID).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization")
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}

func (h *Handler) GetOrganizationInvitations(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	session := handler.GetSession(c)

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var invitations []model.OrganizationInvitation
	if err := database.Connection.
		Where("organization_id = ?", orgID).
		Find(&invitations).
		Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to fetch invitations")
	}

	return handler.SendSuccess(c, invitations)
}

func (h *Handler) InviteMember(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	b, validation := handler.Validate[InviteMemberRequest](
		c,
	)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(
		c,
	)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	invitation := model.OrganizationInvitation{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		OrganizationID: getuint64(orgID),
		InviterID:      membership.ID,
		Email:          b.Email,
	}

	if b.RoleID != nil {
		invitation.InitialOrganizationRoleID = b.RoleID
	}

	if b.WorkspaceID != nil {
		invitation.WorkspaceID = b.WorkspaceID
	}

	if b.WorkspaceRoleID != nil {
		invitation.InitialWorkspaceRoleID = b.WorkspaceRoleID
	}

	if err := database.Connection.Create(&invitation).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to invite member")
	}

	return handler.SendSuccess(c, invitation)
}

func (h *Handler) DiscardInvitation(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	invitationID := c.Params("invitationId")
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	if err := database.Connection.Delete(&model.OrganizationInvitation{
		Model: model.Model{
			ID: getuint64(invitationID),
		},
		OrganizationID: getuint64(orgID),
	}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to dismiss invitation")
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}

func (h *Handler) RemoveMember(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	memberID := c.Params("memberId")

	session := handler.GetSession(
		c,
	)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).Preload("Roles").First(&membership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	if err := database.Connection.Where("organization_id = ? AND user_id = ?", orgID, memberID).Delete(&model.OrganizationMembership{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to remove member")
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}

func (h *Handler) AddMemberRole(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	memberID := c.Params("memberId")
	roleID := c.Params("roleId")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var role model.OrganizationRole
	var assignedMember model.OrganizationMembership

	err := database.Connection.Where("id = ?", roleID).First(&role).Error
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

	err = database.Connection.Exec(
		"INSERT INTO organization_membership_roles (organization_membership_id, organization_role_id) VALUES (?, ?)",
		assignedMember.ID,
		role.ID,
	).Error

	if err != nil {
		log.Println(err)
		return handler.SendInternalServerError(c, err, "Failed to add role")
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}

func (h *Handler) RemoveMemberRole(
	c *fiber.Ctx,
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

	var actingUserMembership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgIDuint64, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&actingUserMembership).
		Error; err != nil {
		log.Printf("Permission check failed for user %d in org %d: %v", session.ActiveSignin.UserID, orgIDuint64, err)
		return handler.SendForbidden(c, nil, "Insufficient permissions to manage roles (user not found in org or DB error).")
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
	isSelfRemoval := (targetMemberShip.UserID == session.ActiveSignin.UserID)

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
			return handler.SendForbidden(c, nil, "Cannot remove your own admin role as you are the sole admin. Please assign this role to another member first.")
		}
	}

	if err := database.Connection.Exec(
		"DELETE FROM organization_membership_roles WHERE organization_membership_id = ? AND organization_role_id = ?",
		targetMembershipIDuint64,
		roleIDToRemoveuint64,
	).Error; err != nil {
		log.Println("Failed to delete role from organization_membership_roles:", err)
		return handler.SendInternalServerError(c, err, "Failed to remove role.")
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}

func (h *Handler) GetOrganizationMembers(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var currentMembership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&currentMembership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var members []model.OrganizationMembership
	if err := database.Connection.Where("organization_id = ?", orgID).
		Preload("Roles").
		Joins("User").
		Joins("User.PrimaryEmailAddress").
		Find(&members).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get organization members")
	}

	return handler.SendSuccess(c, members)
}

func (h *Handler) CreateOrganizationRole(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	session := handler.GetSession(c)
	deployment := handler.GetDeployment(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var currentMembership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&currentMembership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := h.service.hasPermission(currentMembership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions to manage roles.")
	}

	body, validation := handler.Validate[CreateRoleRequest](c)

	if validation != nil {
		return handler.SendBadRequest(c, validation, "Invalid request")
	}

	for _, permission := range body.Permissions {
		if slices.Contains(deployment.B2BSettings.OrganizationPermissions, permission) {
			return handler.SendForbidden(c, nil, "Insufficient permissions to manage roles.")
		}
	}

	role := model.OrganizationRole{
		Model:          model.Model{ID: snowflake.ID()},
		OrganizationID: getuint64(orgID),
	}

	if err := database.Connection.Create(&role).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create organization role")
	}

	if err := database.Connection.Create(&role).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create organization role")
	}

	return handler.SendSuccess(c, role)
}

func (h *Handler) GetOrganizationRoles(
	c *fiber.Ctx,
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
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	roleID := c.Params("roleId")
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var currentMembership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&currentMembership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var role model.OrganizationRole
	if err := database.Connection.
		Where("id = ? AND organization_id = ?", roleID, orgID).
		First(&role).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	if err := database.Connection.Delete(&role).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization role")
	}

	return handler.SendSuccess(c, fiber.Map{})
}

func (h *Handler) GetOrganizationDomains(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var domains []model.OrganizationDomain
	if err := database.Connection.Where("organization_id = ?", orgID).Find(&domains).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get organization domains")
	}

	return handler.SendSuccess(c, domains)
}

func (h *Handler) AddOrganizationDomain(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	d := handler.GetDeployment(c)
	b, validation := handler.Validate[AddDomainRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	requiredPermissions := map[string]bool{
		"organization:owner":  true,
		"organization:admin":  true,
		"organization:manage": true,
	}
	hasPermission := h.service.hasPermission(membership, requiredPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	verificationToken := fmt.Sprintf("wacht-verify-%d", snowflake.ID())

	domain := model.OrganizationDomain{
		ID:                        snowflake.ID(),
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
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	domainID := c.Params("domainId")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	requiredPermissions := map[string]bool{
		"organization:owner":  true,
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
		return handler.SendSuccess(c, fiber.Map{
			"domain": domain,
		})
	}

	const maxVerificationAttempts = 5
	if domain.VerificationAttempts >= maxVerificationAttempts {
		return handler.SendBadRequest(c, nil, "Maximum verification attempts exceeded. Please delete this domain and add it again to retry verification.")
	}

	domain.VerificationAttempts++
	if err := database.Connection.Save(&domain).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to update domain verification attempts")
	}

	fullRecordName := fmt.Sprintf("%s.%s", domain.VerificationDnsRecordName, domain.Fqdn)

	txtRecords, err := net.LookupTXT(fullRecordName)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify domain. Please ensure you've added the TXT record '%s' with value '%s'. Attempts remaining: %d",
			fullRecordName, domain.VerificationDnsRecordData, maxVerificationAttempts-domain.VerificationAttempts)
		return handler.SendBadRequest(c, err, msg)
	}

	verified := slices.Contains(txtRecords, domain.VerificationDnsRecordData)

	if !verified {
		msg := fmt.Sprintf("Verification failed. Please ensure you've added the TXT record '%s' with value '%s'. Attempts remaining: %d",
			fullRecordName, domain.VerificationDnsRecordData, maxVerificationAttempts-domain.VerificationAttempts)
		return handler.SendBadRequest(c, nil, msg)
	}

	domain.Verified = true
	if err := database.Connection.Save(&domain).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to verify domain")
	}

	return handler.SendSuccess(c, fiber.Map{
		"domain": domain,
	})
}

func (h *Handler) DeleteOrganizationDomain(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	domainID := c.Params("domainId")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	requiredPermissions := map[string]bool{
		"organization:owner":  true,
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

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}

func (h *Handler) GetOrganizationBillingAddresses(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var billingAddresses []model.OrganizationBillingAddress
	if err := database.Connection.
		Where("organization_id = ?", getuint64(orgID)).
		Find(&billingAddresses).
		Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get organization billing addresses")
	}

	return handler.SendSuccess(c, billingAddresses)
}

func (h *Handler) AddOrganizationBillingAddress(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	b, validation := handler.Validate[BillingAddressRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	requiredPermissions := map[string]bool{
		"organization:owner":  true,
		"organization:admin":  true,
		"organization:manage": true,
	}
	hasPermission := h.service.hasPermission(membership, requiredPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	billingAddress := model.OrganizationBillingAddress{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		OrganizationID: getuint64(orgID),
		Address:        b.Address,
		City:           b.City,
		State:          b.State,
		Country:        b.Country,
		PostalCode:     b.PostalCode,
	}

	if err := database.Connection.Create(&billingAddress).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to add billing address")
	}

	return handler.SendSuccess(c, fiber.Map{
		"billing_address": billingAddress,
	})
}

func (h *Handler) UpdateOrganizationBillingAddress(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	billingAddressID := c.Params("billingAddressId")
	b, validation := handler.Validate[UpdateBillingAddressRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	requiredPermissions := map[string]bool{
		"organization:owner":  true,
		"organization:admin":  true,
		"organization:manage": true,
	}
	hasPermission := h.service.hasPermission(membership, requiredPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var billingAddress model.OrganizationBillingAddress
	if err := database.Connection.
		Where("id = ? AND organization_id = ?", getuint64(billingAddressID), getuint64(orgID)).
		First(&billingAddress).
		Error; err != nil {
		return handler.SendNotFound(c, nil, "Billing address not found")
	}

	billingAddress.Address = b.Address
	billingAddress.City = b.City
	billingAddress.State = b.State
	billingAddress.Country = b.Country
	billingAddress.PostalCode = b.PostalCode

	if err := database.Connection.Save(&billingAddress).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to update billing address")
	}

	return handler.SendSuccess(c, fiber.Map{
		"billing_address": billingAddress,
	})
}

func (h *Handler) DeleteOrganizationBillingAddress(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	billingAddressID := c.Params("billingAddressId")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	requiredPermissions := map[string]bool{
		"organization:owner":  true,
		"organization:admin":  true,
		"organization:manage": true,
	}
	hasPermission := h.service.hasPermission(membership, requiredPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	if err := database.Connection.
		Delete(&model.OrganizationBillingAddress{OrganizationID: getuint64(orgID), Model: model.Model{ID: getuint64(billingAddressID)}}).
		Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete billing address")
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}
