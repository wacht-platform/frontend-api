package auth

import (
	"github.com/godruoyi/go-snowflake"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"gorm.io/gorm"
)

type AuthService struct {
	db *gorm.DB
}

func NewAuthService() *AuthService {
	return &AuthService{
		db: database.Connection,
	}
}

func (s *AuthService) FindUserByEmail(email string) (*model.UserEmailAddress, error) {
	var userEmail model.UserEmailAddress
	if res := s.db.Where(&model.UserEmailAddress{Email: email}).Joins("User").First(&userEmail); res.RowsAffected == 0 {
		return nil, ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}
	return &userEmail, nil
}

func (s *AuthService) ValidateUserStatus(user *model.UserEmailAddress) error {
	if user.User.Disabled {
		return ErrUserDisabled
	}
	return nil
}

func (s *AuthService) DetermineAuthenticationStep(verified, authenticated, secondFactorEnforced bool, authSettings model.AuthSettings) (model.CurrentSessionStep, bool) {
	var step model.CurrentSessionStep
	completed := false

	if !verified {
		step = model.SessionStepVerifyEmail
	} else if !authenticated {
		if authSettings.FirstFactor == model.FirstFactorEmailPassword {
			step = model.SessionStepVerifyPassword
		} else if authSettings.FirstFactor == model.FirstFactorEmailOTP {
			step = model.SessionStepVerifyEmailOTP
		}
	} else if secondFactorEnforced {
		step = model.SessionStepVerifySecondFactor
	} else {
		completed = true
	}

	return step, completed
}

func (s *AuthService) CreateSignInAttempt(email string, sessionID uint, authenticated bool, secondFactorEnforced bool, step model.CurrentSessionStep, completed bool, lastActiveOrgID uint) *model.SignInAttempt {
	attempt := model.NewSignInAttempt(model.SignInMethodPlain)
	attempt.Method = model.SignInMethodPlain
	attempt.CurrenStep = step
	attempt.Completed = completed
	attempt.Email = email
	attempt.SessionID = sessionID
	attempt.FirstMethodAuthenticated = authenticated
	attempt.SecondMethodAuthenticationRequired = secondFactorEnforced
	attempt.LastActiveOrgID = lastActiveOrgID
	return attempt
}

func (s *AuthService) ValidateSignUpRequest(b *SignUpRequest, d model.Deployment) error {
	if d.AuthSettings.FirstName.Required && b.FirstName == "" {
		return ErrRequiredField("First name")
	}
	if d.AuthSettings.LastName.Required && b.LastName == "" {
		return ErrRequiredField("Last name")
	}
	if d.AuthSettings.EmailAddress.Required && b.Email == "" {
		return ErrRequiredField("Email address")
	}
	if d.AuthSettings.Username.Required && b.Username == "" {
		return ErrRequiredField("Username")
	}
	if d.AuthSettings.Password.Required && b.Password == "" {
		return ErrRequiredField("Password")
	}
	if d.AuthSettings.PhoneNumber.Required && b.PhoneNumber == "" {
		return ErrRequiredField("Phone number")
	}
	return nil
}

func (s *AuthService) CreateUser(b *SignUpRequest, hashedPassword string, deploymentID uint, secondFactorPolicy model.SecondFactorPolicy) model.User {
	return model.User{
		Model:               model.Model{ID: uint(snowflake.ID())},
		FirstName:           b.FirstName,
		LastName:            b.LastName,
		Username:            b.Username,
		Password:            hashedPassword,
		PhoneNumber:         b.PhoneNumber,
		PrimaryEmailAddress: b.Email,
		UserEmailAddresses: []*model.UserEmailAddress{{
			Model:     model.Model{ID: uint(snowflake.ID())},
			Email:     b.Email,
			IsPrimary: true,
		}},
		SchemaVersion:      model.SchemaVersionV1,
		SecondFactorPolicy: secondFactorPolicy,
		DeploymentID:       deploymentID,
	}
}

func (s *AuthService) CreateSocialConnection(userID uint, emailID uint, provider model.SSOProvider, email string, token *oauth2.Token) model.SocialConnection {
	return model.SocialConnection{
		Model:              model.Model{ID: uint(snowflake.ID())},
		Provider:           provider,
		EmailAdress:        email,
		UserID:             userID,
		UserEmailAddressID: emailID,
		AcessToken:         token.AccessToken,
		RefreshToken:       token.RefreshToken,
	}
}

func (s *AuthService) HandleExistingUser(tx *gorm.DB, email *model.UserEmailAddress, token *oauth2.Token, attempt *model.SignInAttempt, deploymentSettings model.AuthSettings) error {
	var connection model.SocialConnection
	for _, sc := range email.User.SocialConnections {
		if sc.Provider == attempt.SSOProvider && sc.EmailAdress == email.Email {
			connection = *sc
			break
		}
	}

	if connection.ID == 0 {
		connection = s.CreateSocialConnection(email.User.ID, email.ID, attempt.SSOProvider, email.Email, token)

		if err := tx.Create(&connection).Error; err != nil {
			return err
		}

		attempt.FirstMethodAuthenticated = true
		attempt.SecondMethodAuthenticationRequired = deploymentSettings.SecondFactorPolicy == model.SecondFactorPolicyEnforced
		if attempt.SecondMethodAuthenticationRequired {
			attempt.CurrenStep = model.SessionStepVerifySecondFactor
		} else {
			attempt.Completed = true
		}

		if attempt.Completed {
			signIn := model.NewSignIn(attempt.SessionID, email.User.ID)
			if err := tx.Create(&signIn).Error; err != nil {
				return err
			}
		}
	}

	return tx.Save(attempt).Error
}

func (s *AuthService) VerifyPassword(storedHash, password string) (bool, error) {
	return utils.ComparePassword(storedHash, password)
}

func (s *AuthService) HashPassword(password string) (string, error) {
	return utils.HashPassword(password)
}

func (s *AuthService) CheckEmailExists(email string) bool {
	var count int64
	s.db.Model(&model.UserEmailAddress{}).Where("email = ?", email).Count(&count)
	return count > 0
}

func getOAuthConfig(provider model.SSOProvider) *oauth2.Config {
	cred := config.GetDefaultOAuthCredentials(string(provider))
	conf := &oauth2.Config{
		ClientID:     cred.ClientID,
		ClientSecret: cred.ClientSecret,
		RedirectURL:  cred.RedirectURI,
		Scopes:       cred.Scopes,
	}

	switch provider {
	case model.SSOProviderGitHub:
		conf.Endpoint = github.Endpoint
	case model.SSOProviderGoogle:
		conf.Endpoint = google.Endpoint
	case model.SSOProviderMicrosoft:
		conf.Endpoint = microsoft.AzureADEndpoint("")
	}

	return conf
}
