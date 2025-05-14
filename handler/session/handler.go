package session

import (
	"log"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/gorm"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) GetCurrentSession(
	c *fiber.Ctx,
) error {
	sessionID := c.Locals("session").(uint64)

	session := new(model.Session)

	err := database.Connection.Joins("ActiveSignin").
		Joins("ActiveSignin.User").
		Preload("ActiveSignin.User.UserEmailAddresses").
		Preload("ActiveSignin.User.UserPhoneNumbers").
		Preload("ActiveSignin.User.SocialConnections").
		Preload("Signins").
		Preload("Signins.User").
		Preload("Signins.User.UserEmailAddresses").
		Preload("Signins.User.UserPhoneNumbers").
		Preload("Signins.User.SocialConnections").
		Where("sessions.id = ?", sessionID).
		First(session).
		Error

	log.Println(session)
	if err != nil {
		log.Println(err)
		return handler.SendNotFound(
			c,
			nil,
			"Session not found",
		)
	}

	return handler.SendSuccess(
		c,
		session,
	)
}

func (h *Handler) SwitchActiveSignIn(
	c *fiber.Ctx,
) error {
	session := handler.GetSession(
		c,
	)

	signInId, err := strconv.ParseUint(
		c.Query("sign_in_id"),
		10,
		64,
	)
	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"Invalid sign in ID",
		)
	}

	validSignIn := false
	for _, signIn := range session.Signins {
		if signIn.ID == uint64(
			signInId,
		) {
			session.ActiveSignin = signIn
			validSignIn = true
			break
		}
	}

	if !validSignIn {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"Invalid sign in ID",
		)
	}

	session.ActiveSigninID = uint64(
		signInId,
	)

	handler.RemoveSessionFromCache(
		session.ID,
	)

	database.Connection.Save(
		session,
	)

	return handler.SendSuccess(
		c,
		session,
	)
}

func (h *Handler) SignOut(
	c *fiber.Ctx,
) error {
	session := handler.GetSession(
		c,
	)

	signInIdStr := c.Query(
		"sign_in_id",
	)

	if signInIdStr != "" {
		signInId, err := strconv.ParseUint(
			signInIdStr,
			10,
			64,
		)
		if err != nil {
			return fiber.NewError(
				fiber.StatusBadRequest,
				"Invalid sign in ID",
			)
		}

		signIn := new(
			model.Signin,
		)
		count := database.Connection.Where("id = ? AND session_id = ?", signInId, session.ID).
			First(signIn).
			RowsAffected

		if count == 0 {
			return fiber.NewError(
				fiber.StatusBadRequest,
				"Sign in not found",
			)
		}

		err = database.Connection.Transaction(
			func(tx *gorm.DB) error {
				tx.Delete(
					signIn,
				)
				tx.Model(session).
					Update("active_sign_in_id", nil)
				return nil
			},
		)
		if err != nil {
			return handler.SendInternalServerError(
				c,
				nil,
				"Failed to sign out",
			)
		}

		handler.RemoveSessionFromCache(
			session.ID,
		)
		return handler.SendSuccess(
			c,
			session,
		)
	} else {
		err := database.Connection.Transaction(func(tx *gorm.DB) error {
			tx.Model(session).Update("active_sign_in_id", nil)
			tx.Where("session_id = ?", session.ID).Delete(&model.Signin{})
			return nil
		})
		if err != nil {
			return handler.SendInternalServerError(c, nil, "Failed to sign out")
		}

		handler.RemoveSessionFromCache(session.ID)
		return handler.SendSuccess(c, session)
	}
}

func (h *Handler) SwitchOrganization(
	c *fiber.Ctx,
) error {
	session := handler.GetSession(c)
	orgID := c.Query("organization_id")

	if session.ActiveSignin == nil {
		return fiber.NewError(fiber.StatusBadRequest, "No active sign in")
	}

	if orgID == "" {
		session.ActiveSignin.User.ActiveOrganizationMembershipID = nil
		database.Connection.Save(session.ActiveSignin.User)
		session.ActiveSignin.ActiveOrganizationID = nil
		database.Connection.Save(session.ActiveSignin)
		handler.RemoveSessionFromCache(session.ID)
		return handler.SendSuccess(c, session)
	}

	orgIDuint64, err := strconv.ParseUint(orgID, 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid org ID")
	}

	membership := new(model.OrganizationMembership)
	count := database.Connection.
		Model(&model.OrganizationMembership{}).
		Where("user_id = ? AND organization_id = ?", session.ActiveSignin.UserID, orgIDuint64).
		First(membership).
		RowsAffected
	if count == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "You are not a member of this organization")
	}

	session.ActiveSignin.User.ActiveOrganizationMembershipID = &membership.ID
	session.ActiveSignin.ActiveOrganizationID = &membership.OrganizationID
	database.Connection.Save(session.ActiveSignin.User)
	database.Connection.Save(session.ActiveSignin)
	handler.RemoveSessionFromCache(session.ID)

	return handler.SendSuccess(c, session)
}

func (h *Handler) SwitchWorkspace(
	c *fiber.Ctx,
) error {
	session := handler.GetSession(c)
	workspaceID := c.Query("workspace_id")

	if session.ActiveSignin == nil {
		return fiber.NewError(fiber.StatusBadRequest, "No active sign in")
	}

	if workspaceID == "" {
		session.ActiveSignin.User.ActiveWorkspaceMembershipID = nil
		session.ActiveSignin.User.ActiveOrganizationMembershipID = nil
		database.Connection.Save(session.ActiveSignin.User)
		session.ActiveSignin.ActiveWorkspaceID = nil
		session.ActiveSignin.ActiveOrganizationID = nil
		database.Connection.Save(session.ActiveSignin)
		handler.RemoveSessionFromCache(session.ID)
		return handler.SendSuccess(c, session)
	}

	workspaceIDuint64, err := strconv.ParseUint(workspaceID, 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid workspace ID")
	}

	membership := new(model.WorkspaceMembership)
	err = database.Connection.
		Model(&model.WorkspaceMembership{}).
		Where("user_id = ? AND workspace_id = ?", session.ActiveSignin.UserID, workspaceIDuint64).
		Joins("Organization").
		First(membership).
		Error
	if err != nil {
		log.Println(err)
		return fiber.NewError(fiber.StatusBadRequest, "You are not a member of this workspace")
	}

	session.ActiveSignin.User.ActiveWorkspaceMembershipID = &membership.ID
	session.ActiveSignin.User.ActiveOrganizationMembershipID = &membership.OrganizationMembershipID
	session.ActiveSignin.ActiveWorkspaceID = &membership.WorkspaceID
	session.ActiveSignin.ActiveOrganizationID = &membership.OrganizationID
	database.Connection.Save(session.ActiveSignin.User)
	database.Connection.Save(session.ActiveSignin)
	handler.RemoveSessionFromCache(session.ID)

	return handler.SendSuccess(c, session)
}
