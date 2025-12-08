package organization

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"slices"
	"strconv"

	"time"

	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"gorm.io/gorm"
	"gorm.io/plugin/dbresolver"
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
			return handler.SendForbidden(c, nil, fmt.Sprintf("You have reached the maximum number of organizations allowed (%d)", d.B2BSettings.MaxOrgsPerUser))
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
			ID: snowflake.ID(),
		},
		OrganizationID: orgid,
		UserID:         *session.ActiveSignin.UserID,
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
			database.Connection.Model(&model.Signin{}).Where("id = ?", session.ActiveSignin.ID).Updates(map[string]any{
				"active_organization_membership_id": membership.ID,
			})
			return nil
		},
	)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create organization")
	}

	utils.PublishWebhookEvent(d.ID, "organization.created", org.ID, "organization")

	utils.RemoveCachedSession(session.ID)

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
				if errDb := database.Connection.Model(&model.Signin{}).Where("id = ?", session.ActiveSignin.ID).Updates(map[string]any{
					"active_organization_membership_id": nil,
					"active_workspace_membership_id":    nil,
				}).Error; errDb != nil {
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
		Preload("Organization").
		Preload("Organization.Segments", "deleted_at IS NULL").
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

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "organization.updated", org.ID, "organization")

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
		log.Println(err)
		return handler.SendForbidden(c, nil, "Only organization owner can delete the organization")
	}

	log.Println(membership.Roles)
	hasPermission := h.service.hasPermission(membership, orgOwnerPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Only organization owner can delete the organization")
	}

	if err := database.Connection.Where("organization_id = ?", orgID).Delete(&model.WorkspaceMembershipRoleAssoc{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization")
	}

	if err := database.Connection.Where("organization_id = ?", orgID).Delete(&model.WorkspaceMembership{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization workspace memberships")
	}

	if err := database.Connection.Where("organization_id = ?", orgID).Delete(&model.WorkspaceRole{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization workspace invitations")
	}

	if err := database.Connection.Where("organization_id = ?", orgID).Delete(&model.Workspace{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization workspace invitations")
	}

	if err := database.Connection.Where("organization_id = ?", orgID).Delete(&model.OrgMembershipRoleAssoc{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization membership role associations")
	}

	if err := database.Connection.Where("organization_id = ?", orgID).Delete(&model.OrganizationMembership{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization memberships")
	}

	if err := database.Connection.Where("organization_id = ?", orgID).Delete(&model.OrganizationInvitation{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization invitations")
	}

	if err := database.Connection.Where("organization_id = ?", orgID).Delete(&model.OrganizationRole{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization workspace roles")
	}

	orgIDUint, _ := strconv.ParseUint(orgID, 10, 64)
	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "organization.deleted", orgIDUint, "organization")

	if err := database.Connection.Delete(&model.Organization{}, orgID).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete organization")
	}

	utils.RemoveCachedSession(session.ID)

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
		Preload("InitialOrganizationRole").
		Preload("Inviter").
		Preload("Inviter.Organization").
		Preload("Inviter.User").
		Preload("Inviter.User.PrimaryEmailAddress").
		Preload("Inviter.Roles").
		Preload("Workspace").
		Preload("InitialWorkspaceRole").
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
			return handler.SendForbidden(c, nil, fmt.Sprintf("Organization has reached the maximum number of members allowed (%d)", d.B2BSettings.MaxAllowedOrgMembers))
		}
	}

	invitation := model.OrganizationInvitation{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		OrganizationID: getuint64(orgID),
		InviterID:      membership.ID,
		Email:          b.Email,
		Token:          token,
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

	// Get deployment and organization details for email
	deployment := handler.GetDeployment(c)
	var organization model.Organization
	database.Connection.First(&organization, getuint64(orgID))

	// Get inviter details
	var inviterUser model.User
	if membership.UserID != 0 {
		database.Connection.First(&inviterUser, membership.UserID)
	}

	// Build invitation link
	inviteLink := fmt.Sprintf("https://%s/invite?token=%s", deployment.FrontendHost, token)

	// Send invitation email via NATS
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

	utils.PublishWebhookEvent(deployment.ID, "organization.invitation.created", invitation.ID, "organization_invitation")

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

	invitationIDUint := getuint64(invitationID)
	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "organization.invitation.revoked", invitationIDUint, "organization_invitation")

	if err := database.Connection.Delete(&model.OrganizationInvitation{
		Model: model.Model{
			ID: invitationIDUint,
		},
		OrganizationID: getuint64(orgID),
	}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to dismiss invitation")
	}

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}

func (h *Handler) AcceptInvitation(
	c *fiber.Ctx,
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

	if session.ActiveSignin == nil || len(session.Signins) == 0 {
		response := AcceptInvitationResponse{
			Message:        "Please sign in to accept this invitation",
			RequiresSignin: true,
			InvitedEmail:   invitation.Email,
			ErrorCode:      handler.ErrCodeInvitationRequiresSignin,
		}
		return handler.SendSuccess(c, response)
	}

	var emailAddress model.UserEmailAddress
	if err := database.Connection.
		Where("email_address = ?", invitation.Email).
		Preload("User").
		First(&emailAddress).Error; err != nil {
		response := AcceptInvitationResponse{
			Message:        fmt.Sprintf("No account exists with email %s. Please sign up first.", invitation.Email),
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
		database.Connection.Delete(&invitation)

		var org model.Organization
		database.Connection.First(&org, invitation.OrganizationID)

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
			ID: snowflake.ID(),
		},
		OrganizationID: invitation.OrganizationID,
		UserID:         *emailAddress.UserID,
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&membership).Error; err != nil {
			return err
		}

		if invitation.InitialOrganizationRoleID != nil {
			if err := tx.Exec(
				"INSERT INTO organization_membership_roles (organization_membership_id, organization_role_id, organization_id) VALUES (?, ?, ?)",
				membership.ID,
				*invitation.InitialOrganizationRoleID,
				invitation.OrganizationID,
			).Error; err != nil {
				return err
			}
		}

		if invitation.WorkspaceID != nil {
			workspaceMembership := model.WorkspaceMembership{
				Model: model.Model{
					ID: snowflake.ID(),
				},
				WorkspaceID:    *invitation.WorkspaceID,
				UserID:         *emailAddress.UserID,
				OrganizationID: invitation.OrganizationID,
			}

			if err := tx.Create(&workspaceMembership).Error; err != nil {
				return err
			}

			if invitation.InitialWorkspaceRoleID != nil {
				if err := tx.Exec(
					"INSERT INTO workspace_membership_roles (workspace_membership_id, workspace_role_id, workspace_id) VALUES (?, ?, ?)",
					workspaceMembership.ID,
					*invitation.InitialWorkspaceRoleID,
					*invitation.WorkspaceID,
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

	var org model.Organization
	database.Connection.First(&org, invitation.OrganizationID)

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
	utils.PublishWebhookEvent(deployment.ID, "organization.invitation.accepted", invitation.ID, "organization_invitation")
	utils.PublishWebhookEvent(deployment.ID, "organization.member.added", membership.ID, "organization_membership")

	return handler.SendSuccess(c, response)
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

	var membershipToRemove model.OrganizationMembership
	if err := database.Connection.Where("organization_id = ? AND user_id = ?", orgID, memberID).First(&membershipToRemove).Error; err != nil {
		return handler.SendNotFound(c, nil, "Member not found")
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "organization.member.removed", membershipToRemove.ID, "organization_membership")

	if err := database.Connection.Delete(&membershipToRemove).Error; err != nil {
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

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "organization.member.role.updated", assignedMember.ID, "organization_membership")

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

	utils.PublishWebhookEvent(d.ID, "organization.member.role.updated", targetMembershipIDuint64, "organization_membership")

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

	// Check current user's membership with raw SQL for better performance
	var currentMembershipExists int
	checkSQL := `
		SELECT 1 FROM organization_memberships
		WHERE organization_memberships.organization_id = ?
			AND organization_memberships.user_id = ?
			AND organization_memberships.deleted_at IS NULL
		LIMIT 1
	`
	if err := database.Connection.Raw(checkSQL, orgID, session.ActiveSignin.UserID).Scan(&currentMembershipExists).Error; err != nil || currentMembershipExists == 0 {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
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
			) as roles_json
		FROM organization_memberships
		JOIN users ON organization_memberships.user_id = users.id
		LEFT JOIN user_email_addresses primary_email ON users.primary_email_address_id = primary_email.id
		WHERE organization_memberships.organization_id = ?
			AND organization_memberships.deleted_at IS NULL
			AND users.deleted_at IS NULL
		ORDER BY organization_memberships.created_at ASC
	`

	if err := database.Connection.Clauses(dbresolver.Read).Raw(rawSQL, orgID).Scan(&queryResults).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get organization members")
	}

	members := make([]model.OrganizationMembership, len(queryResults))
	for i, result := range queryResults {
		members[i] = result.OrganizationMembership

		// Parse user data
		if result.UserJSON != "" {
			var userData model.PublicUserData
			if err := json.Unmarshal([]byte(result.UserJSON), &userData); err != nil {
				log.Printf("Error parsing user data for member %d: %v", members[i].ID, err)
				log.Printf("UserJSON: %s", result.UserJSON)
			} else {
				members[i].User = &userData
			}
		} else {
			log.Printf("No user data JSON for member %d", members[i].ID)
		}

		// Parse roles
		var roles []*model.OrganizationRole
		if result.RolesJSON != "" && result.RolesJSON != "[]" {
			if err := json.Unmarshal([]byte(result.RolesJSON), &roles); err != nil {
				log.Printf("Error parsing roles for member %d: %v", members[i].ID, err)
				log.Printf("RolesJSON: %s", result.RolesJSON)
			} else {
				members[i].Roles = roles
				log.Printf("Successfully parsed %d roles for member %d", len(roles), members[i].ID)
			}
		} else {
			log.Printf("No roles JSON for member %d", members[i].ID)
		}
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

	if !deployment.B2BSettings.CustomOrgRoleEnabled {
		return handler.SendForbidden(c, nil, "Custom organization roles are disabled for this deployment.")
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

	orgIDValue := getuint64(orgID)
	role := model.OrganizationRole{
		Model:          model.Model{ID: snowflake.ID()},
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

func (h *Handler) GetEnterpriseConnections(c *fiber.Ctx) error {
	orgID := c.Params("id")
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		First(&membership).Error; err != nil {
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

func (h *Handler) CreateEnterpriseConnection(c *fiber.Ctx) error {
	orgID := c.Params("id")
	d := handler.GetDeployment(c)
	b, validation := handler.Validate[CreateEnterpriseConnectionRequest](c)
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
		First(&membership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	hasPermission := h.service.hasPermission(membership, orgManagementPermissions)
	if !hasPermission {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
	}

	connection := model.EnterpriseConnection{
		ID:             snowflake.ID(),
		OrganizationID: getuint64(orgID),
		DeploymentID:   d.ID,
		Protocol:       b.Protocol,
	}

	// Handle domain if provided
	if b.DomainID != 0 {
		var domain model.OrganizationDomain
		if err := database.Connection.
			Where("id = ? AND organization_id = ? AND verified = true", b.DomainID, orgID).
			First(&domain).Error; err != nil {
			return handler.SendBadRequest(c, nil, "Domain must be verified before configuring SSO")
		}
		connection.DomainID = &b.DomainID
	}

	// Set protocol-specific fields
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

	if err := database.Connection.Create(&connection).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create enterprise connection")
	}

	return handler.SendSuccess(c, connection)
}

func (h *Handler) UpdateEnterpriseConnection(c *fiber.Ctx) error {
	orgID := c.Params("id")
	connectionID := c.Params("connectionId")
	b, validation := handler.Validate[UpdateEnterpriseConnectionRequest](c)
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
		First(&membership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
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

	// Common fields
	if b.DomainID != nil {
		connection.DomainID = b.DomainID
	}

	// SAML fields
	if b.IdpEntityID != nil {
		connection.IdpEntityID = *b.IdpEntityID
	}
	if b.IdpSSOURL != nil {
		connection.IdpSSOURL = *b.IdpSSOURL
	}
	if b.IdpCertificate != nil {
		connection.IdpCertificate = *b.IdpCertificate
	}

	// OIDC fields
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

	if err := database.Connection.Save(&connection).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to update enterprise connection")
	}

	return handler.SendSuccess(c, connection)
}

func (h *Handler) DeleteEnterpriseConnection(c *fiber.Ctx) error {
	orgID := c.Params("id")
	connectionID := c.Params("connectionId")

	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	var membership model.OrganizationMembership
	if err := database.Connection.
		Where("organization_id = ? AND user_id = ?", orgID, session.ActiveSignin.UserID).
		Preload("Roles").
		First(&membership).Error; err != nil {
		return handler.SendForbidden(c, nil, "Insufficient permissions")
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

	return handler.SendSuccess(c, fiber.Map{
		"success": true,
	})
}
