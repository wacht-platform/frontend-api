package auth

import (
	"log"

	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"gorm.io/gorm"
)

func SignIn(c *fiber.Ctx) error {
	b, verr := handler.Validate[SignInRequest](c)

	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	d := handler.GetDeployment(c)

	var u model.User
	err := database.Connection.Where(&model.User{UserEmailAddresses: []model.UserEmailAddress{{Email: b.Email}}}).First(&u).Error

	if err != nil {
		return handler.SendNotFound(c, nil, "User not found")
	}

	if u.Disabled {
		return handler.SendForbidden(c, nil, "User is disabled")
	}

	secondFactorEnforced := d.AuthSettings.SecondFactorPolicy == model.SecondFactorPolicyEnforced ||
		u.SecondFactorPolicy == model.SecondFactorPolicyEnforced

	authenticated := false

	if b.Password != "" {
		match, err := utils.ComparePassword(u.Password, b.Password)

		if err != nil {
			return handler.SendInternalServerError(c, nil, "Error comparing password")
		}

		if !match {
			return handler.SendUnauthorized(c, nil, "Invalid credentials")
		}

		authenticated = true
	}

	session := model.NewSession()
	attempt := model.NewSignInAttempt(model.SignInMethodPlain)
	attempt.Method = model.SignInMethodPlain

	if !authenticated {
		attempt.FirstMethodAuthenticated = false
		if d.AuthSettings.FirstFactor == model.FirstFactorEmailPassword {
			attempt.CurrenStep = model.SessionStepVerifyPassword
		}
		if d.AuthSettings.FirstFactor == model.FirstFactorEmailOTP {
			attempt.CurrenStep = model.SessionStepVerifyEmailOTP
		}
	} else if secondFactorEnforced {
		attempt.FirstMethodAuthenticated = true
		attempt.SecondMethodAuthenticationRequired = true
		attempt.CurrenStep = model.SessionStepVerifySecondFactor
	} else {
		attempt.FirstMethodAuthenticated = true
		attempt.CurrenStep = model.SessionStepVerifySecondFactor
	}

	attempt.LastActiveOrgID = u.LastActiveOrgID

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		err = tx.Create(&session).Error

		if err != nil {
			return err
		}

		attempt.SessionID = session.ID

		err = tx.Create(&attempt).Error

		session.SignInAttempts = append(session.SignInAttempts, *attempt)

		return err
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	return handler.SendSuccess(c, session)
}

func SignUp(c *fiber.Ctx) error {
	b, verr := handler.Validate[SignUpRequest](c)

	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	d := handler.GetDeployment(c)

	var u model.User

	queryStr := "deployments_id = ?"
	queryProps := []any{
		d.ID,
	}

	if d.AuthSettings.FirstName.Required && b.FirstName == "" {
		return handler.SendBadRequest(c, nil, "First name is required")
	}

	if d.AuthSettings.LastName.Required && b.LastName == "" {
		return handler.SendBadRequest(c, nil, "Last name is required")
	}

	if d.AuthSettings.EmailAddress.Required && b.Email == "" {
		return handler.SendBadRequest(c, nil, "Email address is required")
	}

	if d.AuthSettings.Username.Required && b.Username == "" {
		return handler.SendBadRequest(c, nil, "Username is required")
	} else if b.Username != "" {
		queryStr += "username = ?"
		queryProps = append(queryProps, b.Username)
	}

	if d.AuthSettings.Password.Required && b.Password == "" {
		return handler.SendBadRequest(c, nil, "Password is required")
	}

	if d.AuthSettings.PhoneNumber.Required && b.PhoneNumber == "" {
		return handler.SendBadRequest(c, nil, "Phone number is required")
	} else if b.PhoneNumber != "" {
		queryStr += "phone_number = ?"
		queryProps = append(queryProps, b.PhoneNumber)
	}

	if d.AuthSettings.EmailAddress.Required && b.Email != "" {
		var email model.UserEmailAddress

		err := database.Connection.Where("email = ?", b.Email).First(&email).Error

		if err == nil {
			return handler.SendBadRequest(c, nil, "Email address already exists")
		}
	}

	err := database.Connection.Where(queryStr, queryProps...).First(&u).Error

	if err == nil {
		return handler.SendBadRequest(c, nil, "User already exists")
	}

	hashedPassword, err := utils.HashPassword(b.Password)

	if err != nil {
		return handler.SendInternalServerError(c, err, "Error hashing password")
	}

	u = model.User{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		FirstName:           b.FirstName,
		LastName:            b.LastName,
		Username:            b.Username,
		Password:            hashedPassword,
		PhoneNumber:         b.PhoneNumber,
		PrimaryEmailAddress: b.Email,
		UserEmailAddresses: []model.UserEmailAddress{
			{
				Model: model.Model{
					ID: uint(snowflake.ID()),
				},
				Email:     b.Email,
				IsPrimary: true,
			},
		},
		SchemaVersion:      model.SchemaVersionV1,
		SecondFactorPolicy: d.AuthSettings.SecondFactorPolicy,
		DeplymentId:        d.ID,
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		err = tx.Create(&u).Error

		return err
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	session := model.NewSession()
	attempt := model.NewSignInAttempt(model.SignInMethodPlain)
	attempt.Method = model.SignInMethodPlain

	attempt.FirstMethodAuthenticated = false
	attempt.CurrenStep = model.SessionStepVerifyEmailOTP
	attempt.SecondMethodAuthenticationRequired = d.AuthSettings.SecondFactorPolicy == model.SecondFactorPolicyEnforced

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		err = tx.Create(&session).Error

		if err != nil {
			return err
		}

		attempt.SessionID = session.ID

		err = tx.Create(&attempt).Error

		session.SignInAttempts = append(session.SignInAttempts, *attempt)

		return err
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	return handler.SendSuccess(c, session)
}

func AuthMethods(c *fiber.Ctx) error {
	d := handler.GetDeployment(c)

	// var firstFactors []string
	// var secondFactors []string

	return handler.SendSuccess(c, d.AuthSettings)
}

func InitSSO(c *fiber.Ctx) error {
	provider := c.Query("provider")

	if provider == "" {
		return handler.SendBadRequest(c, nil, "Provider is required")
	}

	session := model.NewSession()

	attempt := model.NewSignInAttempt(model.SignInMethodSSO)
	attempt.SSOProvider = model.SSOProvider(provider)

	url := utils.GenerateVerificationUrl(model.SSOProvider(provider), *attempt)

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		err := tx.Create(&session).Error

		if err != nil {
			return err
		}

		attempt.SessionID = session.ID

		err = tx.Create(&attempt).Error

		session.SignInAttempts = append(session.SignInAttempts, *attempt)

		return err
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	return handler.SendSuccess(c, fiber.Map{
		"oauth_url": url,
	})
}

func SSOCallback(c *fiber.Ctx) error {
	code := c.Query("code")

	if code == "" {
		return handler.SendBadRequest(c, nil, "Code is required")
	}

	atm := model.SignInAttempt{}

	err := database.Connection.Where("id = ?", c.Query("state")).First(&atm).Error

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	defcred := config.GetDefaultOAuthCredentials(string(atm.SSOProvider))
	conf := &oauth2.Config{
		ClientID:     defcred.ClientID,
		ClientSecret: defcred.ClientSecret,
		RedirectURL:  defcred.RedirectURI,
		Scopes:       defcred.Scopes,
	}

	switch atm.SSOProvider {
	case model.SSOProviderX:
	case model.SSOProviderGitHub:
		conf.Endpoint = github.Endpoint
	case model.SSOProviderGitLab:
	case model.SSOProviderGoogle:
		conf.Endpoint = google.Endpoint
	case model.SSOProviderFacebook:
	case model.SSOProviderMicrosoft:
		conf.Endpoint = microsoft.AzureADEndpoint("")
	case model.SSOProviderLinkedIn:
	case model.SSOProviderDiscord:
	}

	token, err := conf.Exchange(c.Context(), code)

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	if token.Valid() {
		log.Println(token.AccessToken)
		// use the token to get the user profile
	}

	return handler.SendSuccess(c, fiber.Map{})
}
