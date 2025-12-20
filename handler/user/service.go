package user

import (
	"context"
	"fmt"
	"mime/multipart"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/service"
	"github.com/ilabs/wacht-fe/utils"
	"gorm.io/gorm"
)

const otpExpirationTime = 5 * time.Minute

type UserService struct {
	db   *gorm.DB
	s3   *service.S3Service
	nats *service.NatsService
}

func NewUserService() *UserService {
	natsService, err := service.NewNatsService()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize NATS service: %v", err))
	}

	return &UserService{
		db:   database.Connection,
		s3:   service.NewS3Service(),
		nats: natsService,
	}
}

func (s *UserService) storeOTPInCache(key string, otp string) error {
	return database.Redis.Set(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
		otp,
		otpExpirationTime,
	).Err()
}

func (s *UserService) removeOTPFromCache(key string) error {
	return database.Redis.Del(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
	).Err()
}

func (s *UserService) getOTPFromCache(key string) (string, error) {
	return database.Redis.Get(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
	).Result()
}

func (s *UserService) sendEmailOTPVerificationAsync(
	deploymentID uint64,
	email model.UserEmailAddress,
	code string,
	ip string,
	userAgent string,
) error {
	return s.nats.SendVerificationEmail(deploymentID, *email.UserID, email.EmailAddress, code, ip, userAgent)
}

func (s *UserService) sendSmsOTPVerification(
	deploymentID uint64,
	userID uint64,
	phoneNumber string,
	countryCode string,
) error {
	return s.nats.SendOTPSMS(deploymentID, userID, phoneNumber, countryCode)
}

func (s *UserService) verifyPhoneOTP(
	deploymentID uint64,
	phoneNumber string,
	countryCode string,
	code string,
) (bool, error) {
	return utils.VerifyPhoneOTP(deploymentID, phoneNumber, code)
}

func (s *UserService) uploadProfilePicture(
	userID uint64,
	file *multipart.FileHeader,
) (string, error) {
	reader, err := file.Open()
	if err != nil {
		return "", err
	}

	return s.s3.UploadToCdn(fmt.Sprintf("users/%d", userID), reader)
}

func (s *UserService) ValidateEmailRestrictions(email string, restrictions model.DeploymentRestrictions) error {
	if restrictions.AllowlistEnabled && len(restrictions.AllowlistedResources) > 0 {
		allowed := false
		emailDomain := strings.Split(email, "@")[1]
		for _, allowedResource := range restrictions.AllowlistedResources {
			if email == allowedResource || emailDomain == allowedResource {
				allowed = true
				break
			}
		}
		if !allowed {
			return handler.ErrEmailNotAllowed
		}
	}

	if restrictions.BlocklistEnabled && len(restrictions.BlocklistedResources) > 0 {
		emailDomain := strings.Split(email, "@")[1]
		for _, blockedResource := range restrictions.BlocklistedResources {
			if email == blockedResource || emailDomain == blockedResource {
				return handler.ErrEmailBlocked
			}
		}
	}

	if restrictions.BlockDisposableEmails {
		if service.IsDisposableEmailDomain(email) {
			return handler.ErrDisposableEmail
		}
	}

	if err := s.validateEmailMXRecord(email); err != nil {
		return handler.ErrEmailNotAllowed
	}

	return nil
}

func (s *UserService) ValidatePhoneRestrictions(phoneNumber string, countryCode string, restrictions model.DeploymentRestrictions) error {
	abstractAPIService := service.NewAbstractAPIService(
		config.GetEnv("ABSTRACT_API_KEY", ""),
	)

	if abstractAPIService.APIKey == "" {
		return fmt.Errorf("phone validation service not configured")
	}

	result, err := abstractAPIService.ValidatePhoneNumber(phoneNumber, countryCode)
	if err != nil {
		return fmt.Errorf("phone validation failed: %w", err)
	}

	if !result.IsValid {
		return handler.ErrVoipNumberBlocked
	}

	if result.IsBlocked {
		return handler.ErrVoipNumberBlocked
	}

	if restrictions.BlockVoipNumbers && result.IsVOIP {
		return handler.ErrVoipNumberBlocked
	}

	if restrictions.BlockVoipNumbers && result.IsHighRisk {
		return handler.ErrVoipNumberBlocked
	}

	if restrictions.CountryRestrictions.Enabled && len(restrictions.CountryRestrictions.CountryCodes) > 0 {
		allowed := false
		for _, allowedCountry := range restrictions.CountryRestrictions.CountryCodes {
			if result.CountryCode == allowedCountry {
				allowed = true
				break
			}
		}
		if !allowed {
			return handler.ErrCountryRestricted
		}
	}

	return nil
}

func (s *UserService) extractCountryCodeFromPhone(phoneNumber string) string {
	digits := regexp.MustCompile(`\D`).ReplaceAllString(phoneNumber, "")

	if strings.HasPrefix(digits, "1") && len(digits) == 11 {
		return "US"
	}
	if strings.HasPrefix(digits, "44") {
		return "GB"
	}
	if strings.HasPrefix(digits, "49") {
		return "DE"
	}
	if strings.HasPrefix(digits, "33") {
		return "FR"
	}
	if strings.HasPrefix(digits, "81") {
		return "JP"
	}
	if strings.HasPrefix(digits, "86") {
		return "CN"
	}
	if strings.HasPrefix(digits, "91") {
		return "IN"
	}

	return "XX"
}

func (s *UserService) validateEmailMXRecord(email string) error {
	domain := strings.Split(email, "@")[1]

	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		_, err := net.LookupHost(domain)
		if err != nil {
			return fmt.Errorf("invalid email domain: %s", domain)
		}
	}

	return nil
}

func (s *UserService) ValidatePasswordRemoval(user *model.User, deployment *model.Deployment) error {
	authSettings := deployment.AuthSettings
	hasAlternativeMethod := false

	if authSettings.FirstFactor == model.FirstFactorEmailOTP {
		for _, email := range user.UserEmailAddresses {
			if email.Verified {
				hasAlternativeMethod = true
				break
			}
		}
	}

	if authSettings.MagicLink != nil && authSettings.MagicLink.Enabled {
		for _, email := range user.UserEmailAddresses {
			if email.Verified {
				hasAlternativeMethod = true
				break
			}
		}
	}

	if authSettings.Passkey != nil && authSettings.Passkey.Enabled {
		hasAlternativeMethod = true
	}

	if len(user.SocialConnections) > 0 {
		for _, socialConn := range deployment.SocialConnections {
			if socialConn.Enabled {
				hasAlternativeMethod = true
				break
			}
		}
	}

	if authSettings.AuthFactorsEnabled.PhoneOTP {
		for _, phone := range user.UserPhoneNumbers {
			if phone.Verified {
				hasAlternativeMethod = true
				break
			}
		}
	}

	if !hasAlternativeMethod {
		return handler.ErrNoAlternativeAuthMethod
	}

	return nil
}
