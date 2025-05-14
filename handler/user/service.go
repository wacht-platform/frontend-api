package user

import (
	"context"
	"fmt"
	"mime/multipart"
	"net/smtp"
	"time"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/service"
	"gorm.io/gorm"
)

const otpExpirationTime = 5 * time.Minute

type UserService struct {
	db  *gorm.DB
	sns *service.SnsService
	s3  *service.S3Service
}

func NewUserService() *UserService {
	return &UserService{
		db:  database.Connection,
		sns: service.NewSnsService(),
		s3:  service.NewS3Service(),
	}
}

func (s *UserService) storeOTPInCache(key string, otp string) error {
	return database.Cache.Set(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
		otp,
		otpExpirationTime,
	).Err()
}

func (s *UserService) removeOTPFromCache(key string) error {
	return database.Cache.Del(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
	).Err()
}

func (s *UserService) getOTPFromCache(key string) (string, error) {
	return database.Cache.Get(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
	).Result()
}

func (s *UserService) sendEmailOTPVerification(
	email string,
	otp string,
) error {
	smtpHost := "smtp.zeptomail.in"
	smtpPort := "587"
	username := "emailapikey"
	password := "PHtE6r1cR7rsgmEsoEMI4vPsRMWlZ41/r75kK1EWstkUA6NRGE0H+dt9kmPkoxopA6NGEvKZyNlgsrLK5rmDIT7qMjtEWWqyqK3sx/VYSPOZsbq6x00VtFoedELVU4TodNJj0Czfs97bNA=="
	from := "notifications@wacht.tech"

	auth := smtp.PlainAuth("", username, password, smtpHost)

	htmlBody := fmt.Sprintf(`
  <div style="font-family: Helvetica, Arial, sans-serif; max-width: 90%%; margin: auto; line-height: 1.6; color: #333; padding: 20px; box-sizing: border-box;">
    <div style="margin: auto; padding: 20px; background: #f9f9f9; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">
      <div style="border-bottom: 2px solid #000; padding-bottom: 10px; margin-bottom: 20px;">
        <a href="#" style="font-size: 1.5em; color: #000; text-decoration: none; font-weight: bold;">Intellinesia</a>
      </div>
      <p style="font-size: 1.2em; margin-bottom: 10px;">Hi,</p>
      <p style="margin-bottom: 20px;">Thank you for choosing Wacht. Use the following OTP to complete your Sign Up procedures. OTP is valid for 5 minutes:</p>
      <h2 style="background: #000; color: #fff; padding: 10px 20px; border-radius: 5px; display: inline-block; margin: 0 auto;">%s</h2>
      <p style="font-size: 1em; margin-top: 20px;">Regards,<br><strong>Wacht</strong></p>
      <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
      <div style="text-align: right; color: #aaa; font-size: 0.9em; line-height: 1.4;">
        <p style="margin: 0;">Intellinesia LTD</p>
        <p style="margin: 0;">Kolkata</p>
        <p style="margin: 0;">India</p>
      </div>
    </div>
  </div>
  `, otp)

	fromstr := fmt.Sprintf(
		"From: Security Notifications <%s>\r\n",
		from,
	)
	subject := "Subject: Your OTP Code\r\n"
	contentType := "MIME-Version: 1.0\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n"
	msg := []byte(fromstr + subject + contentType + htmlBody)

	smtpServer := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
	err := smtp.SendMail(smtpServer, auth, from, []string{email}, msg)
	if err != nil {
		return fmt.Errorf(
			"failed to send email to %s: %w",
			email,
			err,
		)
	}

	return nil
}

func (s *UserService) sendSmsOTPVerification(
	phone string,
	otp string,
) error {
	message := fmt.Sprintf(
		"Your Wacht verification code is: %s. This code will expire in 5 minutes.",
		otp,
	)

	return s.sns.SendSMS(phone, message)
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
