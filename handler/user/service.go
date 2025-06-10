package user

import (
	"context"
	"fmt"
	"mime/multipart"
	"time"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/service"
	"gorm.io/gorm"
)

const otpExpirationTime = 5 * time.Minute

type UserService struct {
	db     *gorm.DB
	sns    *service.SnsService
	s3     *service.S3Service
	celery *service.CeleryService
}

func NewUserService() *UserService {
	return &UserService{
		db:     database.Connection,
		sns:    service.NewSnsService(),
		s3:     service.NewS3Service(),
		celery: service.NewCeleryService(),
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
	email string,
) error {
	return s.celery.SendEmailAsync("user_email_verification", deploymentID, email)
}

func (s *UserService) sendSmsOTPVerificationAsync(
	deploymentID uint64,
	phone string,
) error {
	return s.celery.SendSMSAsync("user_sms_verification", deploymentID, phone)
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
