package auth

import (
	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"gorm.io/gorm"
)

type Handler struct {
	service *AuthService
}

func NewHandler() *Handler {
	return &Handler{
		service: NewAuthService(),
	}
}

func (h *Handler) SignIn(c *fiber.Ctx) error {
	b, verr := handler.Validate[SignInRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

	email, err := h.service.FindUserByEmail(b.Email)
	if err != nil {
		if err == ErrUserNotFound {
			return handler.SendNotFound(c, nil, err.Error())
		}
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	if err := h.service.ValidateUserStatus(email); err != nil {
		return handler.SendForbidden(c, nil, err.Error())
	}

	secondFactorEnforced := d.AuthSettings.SecondFactorPolicy == model.SecondFactorPolicyEnforced ||
		email.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced

	authenticated := false
	if b.Password != "" {
		match, err := h.service.VerifyPassword(email.User.Password, b.Password)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error comparing password")
		}
		if !match {
			return handler.SendUnauthorized(c, nil, ErrInvalidCredentials.Error())
		}
		authenticated = true
	}

	step, completed := h.service.DetermineAuthenticationStep(authenticated, secondFactorEnforced, d.AuthSettings)
	attempt := h.service.CreateSignInAttempt(b.Email, session.ID, authenticated, secondFactorEnforced, step, completed, email.User.LastActiveOrgID)

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		if completed && email.User.ID != 0 {
			signIn := model.NewSignIn(session.ID, email.User.ID)
			if err := tx.Create(signIn).Error; err != nil {
				return err
			}
			session.SignIns = append(session.SignIns, *signIn)
			session.ActiveSignInID = signIn.ID
		}

		session.SignInAttempts = append(session.SignInAttempts, *attempt)
		return nil
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	return handler.SendSuccess(c, session)
}

func (h *Handler) SignUp(c *fiber.Ctx) error {
	b, verr := handler.Validate[SignUpRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if err := h.service.ValidateSignUpRequest(b, d); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	if b.Email != "" && h.service.CheckEmailExists(b.Email) {
		return handler.SendBadRequest(c, nil, ErrEmailExists.Error())
	}

	hashedPassword, err := h.service.HashPassword(b.Password)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error hashing password")
	}

	u := h.service.CreateUser(b, hashedPassword, d.ID, d.AuthSettings.SecondFactorPolicy)
	completed := !d.AuthSettings.VerificationPolicy.Email
	attempt := h.service.CreateSignInAttempt(b.Email, session.ID, false, false, model.SessionStepVerifyEmailOTP, completed, 0)

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&u).Error; err != nil {
			return err
		}

		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		session.SignInAttempts = append(session.SignInAttempts, *attempt)
		return nil
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	return handler.SendSuccess(c, u)
}

func (h *Handler) AuthMethods(c *fiber.Ctx) error {
	d := handler.GetDeployment(c)
	return handler.SendSuccess(c, d.AuthSettings)
}

func (h *Handler) InitSSO(c *fiber.Ctx) error {
	provider := model.SSOProvider(c.Query("provider"))
	if provider == "" {
		return handler.SendBadRequest(c, nil, ErrProviderRequired.Error())
	}

	session := handler.GetSession(c)
	attempt := model.NewSignInAttempt(model.SignInMethodSSO)
	attempt.Method = model.SignInMethodSSO
	attempt.SessionID = session.ID
	attempt.SSOProvider = provider

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}
		session.SignInAttempts = append(session.SignInAttempts, *attempt)
		return nil
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	url := utils.GenerateVerificationUrl(provider, *attempt)
	return handler.SendSuccess(c, fiber.Map{
		"oauth_url": url,
		"session":   session,
	})
}

func (h *Handler) SSOCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	deployment := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if code == "" {
		return handler.SendBadRequest(c, nil, ErrCodeRequired.Error())
	}

	var attempt model.SignInAttempt
	if err := database.Connection.Where("id = ?", c.Query("state")).First(&attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, ErrInvalidState.Error())
	}

	conf := getOAuthConfig(attempt.SSOProvider)
	token, err := conf.Exchange(c.Context(), code)
	if err != nil || !token.Valid() {
		return handler.SendBadRequest(c, nil, ErrInvalidCode.Error())
	}

	user, err := utils.ExchangeTokenForUser(token, attempt.SSOProvider)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get user info")
	}

	var email model.UserEmailAddress
	exists := database.Connection.Joins("User", database.Connection.Where(&model.User{DeploymentID: deployment.ID})).
		Preload("User.SocialConnections").Where("email = ?", user.Email).
		First(&email).RowsAffected > 0

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if exists {
			return h.service.HandleExistingUser(tx, &email, token, &attempt, deployment.AuthSettings)
		}

		u := model.User{
			Model:               model.Model{ID: uint(snowflake.ID())},
			PrimaryEmailAddress: user.Email,
			SchemaVersion:       model.SchemaVersionV1,
			SecondFactorPolicy:  deployment.AuthSettings.SecondFactorPolicy,
			DeploymentID:        deployment.ID,
		}

		if err := tx.Create(&u).Error; err != nil {
			return err
		}

		email := model.UserEmailAddress{
			Model:     model.Model{ID: uint(snowflake.ID())},
			Email:     user.Email,
			IsPrimary: true,
			UserID:    u.ID,
		}

		if err := tx.Create(&email).Error; err != nil {
			return err
		}

		connection := h.service.CreateSocialConnection(u.ID, email.ID, attempt.SSOProvider, user.Email, token)
		signIn := model.NewSignIn(session.ID, u.ID)

		if err := tx.Create(&connection).Error; err != nil {
			return err
		}

		if err := tx.Create(&signIn).Error; err != nil {
			return err
		}

		session.SignIns = append(session.SignIns, *signIn)
		return nil
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	return handler.SendSuccess(c, session)
}
