package organization

import (
	"fmt"
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

func getUint(s string) uint {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		panic("invalid organization id")
	}
	return uint(v)
}

func (h *Handler) CreateOrganization(
	c *fiber.Ctx,
) error {
	d := handler.GetDeployment(c)
	b, verr := handler.Validate[CreateOrgRequest](c)
	img, _ := c.FormFile("image")
	imgUrl := d.UISettings.DefaultOrganizationProfileImageURL
	orgId := uint(snowflake.ID())

	if img != nil {
		url, err := h.service.UploadOrganizationImage(orgId, img)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Failed to upload organization image")
		}
		imgUrl = url
	}

	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	org := model.Organization{
		Model: model.Model{
			ID: orgId,
		},
		DeploymentID: d.ID,
		Name:         b.Name,
		Description:  b.Description,
		ImageUrl:     imgUrl,
	}

	membership := model.OrganizationMembership{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		OrganizationID: orgId,
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
					"INSERT INTO %s (organization_membership_id, deployment_organization_role_id) VALUES (?, ?)",
					"org_membership_roles",
				),
				membership.ID,
				d.B2BSettings.DefaultOrgCreatorRoleID,
			).Error; err != nil {
				return err
			}
			session.ActiveSignin.ActiveOrganizationID = &orgId
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
	orgID := c.Params("id")
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	err := database.Connection.Transaction(
		func(tx *gorm.DB) error {
			if err := tx.
				Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
				First(&membership).
				Error; err != nil {
				return err
			}

			if err := tx.Delete(&model.WorkspaceMembership{OrganizationMembershipID: membership.ID}).
				Error; err != nil {
				return err
			}

			if err := tx.Delete(&membership).Error; err != nil {
				return err
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
	b, verr := handler.Validate[UpdateOrgRequest](
		c,
	)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	session := handler.GetSession(
		c,
	)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var org model.Organization
	if err := database.Connection.First(&org, orgID).Error; err != nil {
		return handler.SendNotFound(c, nil, "Organization not found")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Role").First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	if b.Name != "" {
		org.Name = b.Name
	}

	if b.Description != "" {
		org.Description = b.Description
	}

	if len(b.WhitelistedIPs) > 0 {
		org.WhitelistedIPs = b.WhitelistedIPs
	}

	if b.AutoAssignedWorkspaceID != 0 {
		org.AutoAssignedWorkspaceID = b.AutoAssignedWorkspaceID
	}

	if err := database.Connection.Save(&org).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to update organization")
	}

	return handler.SendSuccess(c, fiber.Map{
		"organization": org,
	})
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
		Preload("Role").First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Only organization owner can delete the organization")
	}

	isOwner := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" {
			isOwner = true
			break
		}
	}

	if !isOwner {
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
		Preload("Role").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" {
			hasPermission = true
			break
		}
	}

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
	b, verr := handler.Validate[InviteMemberRequest](
		c,
	)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
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
		Preload("Role").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
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
		return handler.SendBadRequest(c, nil, "User is already a member")
	}

	newMembership := model.OrganizationMembership{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		OrganizationID: uint(
			snowflake.ID(),
		),
		UserID: userEmail.UserID,
		Role:   []*model.OrganizationRole{},
	}

	err := database.Connection.Transaction(
		func(tx *gorm.DB) error {
			if err := tx.Create(&newMembership).Error; err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to add member")
	}

	return handler.SendSuccess(c, fiber.Map{
		"membership": newMembership,
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
	if err := database.Connection.Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).Preload("Role").First(&membership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" {
			hasPermission = true
			break
		}
	}

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
		Preload("Role").
		First(&currentMembership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var members []model.OrganizationMembership
	if err := database.Connection.Where("organization_id = ?", orgID).
		Preload("Role").
		Find(&members).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get organization members")
	}

	return handler.SendSuccess(c, members)
}

func (h *Handler) GetOrganizationRoles(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var roles []model.OrganizationRole
	if err := database.Connection.Where("organization_id = ?", orgID).Find(&roles).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get organization roles")
	}

	return handler.SendSuccess(c, roles)
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
	b, verr := handler.Validate[AddDomainRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Role").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" || role.Name == "organization:admin" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var existingDomain model.OrganizationDomain
	if err := database.Connection.Where("organization_id = ? AND domain = ?", orgID, b.Domain).First(&existingDomain).Error; err == nil {
		return handler.SendBadRequest(c, nil, "Domain already exists for this organization")
	}

	verificationToken := fmt.Sprintf("wacht-verify-%d", snowflake.ID())

	domain := model.OrganizationDomain{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		OrganizationID:            getUint(orgID),
		Domain:                    b.Domain,
		Verified:                  false,
		VerificationDnsRecordType: "TXT",
		VerificationDnsRecordName: "_wacht-verification",
		VerificationDnsRecordData: verificationToken,
		VerificationAttempts:      0,
	}

	if err := database.Connection.Create(&domain).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to add domain")
	}

	return handler.SendSuccess(c, fiber.Map{
		"domain": domain,
	})
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
		Preload("Role").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" || role.Name == "organization:admin" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var domain model.OrganizationDomain
	if err := database.Connection.
		Where("id = ? AND organization_id = ?", getUint(domainID), getUint(orgID)).
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

	fullRecordName := fmt.Sprintf("%s.%s", domain.VerificationDnsRecordName, domain.Domain)

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
		Preload("Role").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" || role.Name == "organization:admin" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	if err := database.Connection.
		Delete(&model.OrganizationDomain{OrganizationID: getUint(orgID), Model: model.Model{ID: getUint(domainID)}}).
		Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete domain")
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}

// Get all billing addresses for an organization
func (h *Handler) GetOrganizationBillingAddresses(
	c *fiber.Ctx,
) error {
	orgID := c.Params("id")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	// Check if user is member of organization
	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	// Get all billing addresses for organization
	var billingAddresses []model.OrganizationBillingAddress
	if err := database.Connection.
		Where("organization_id = ?", getUint(orgID)).
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
	b, verr := handler.Validate[BillingAddressRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Role").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" || role.Name == "organization:admin" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	billingAddress := model.OrganizationBillingAddress{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		OrganizationID: getUint(orgID),
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
	b, verr := handler.Validate[UpdateBillingAddressRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Role").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" || role.Name == "organization:admin" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	var billingAddress model.OrganizationBillingAddress
	if err := database.Connection.
		Where("id = ? AND organization_id = ?", getUint(billingAddressID), getUint(orgID)).
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

// Delete a billing address
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
		Preload("Role").
		First(&membership).
		Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := false
	for _, role := range membership.Role {
		if role.Name == "organization:owner" || role.Name == "organization:admin" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	if err := database.Connection.
		Delete(&model.OrganizationBillingAddress{OrganizationID: getUint(orgID), Model: model.Model{ID: getUint(billingAddressID)}}).
		Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete billing address")
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}
