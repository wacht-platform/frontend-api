package config

import (
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
)

var R2Session *session.Session

func InitR2Session() error {
	sess, err := session.NewSession(&aws.Config{
		Endpoint:         aws.String(os.Getenv("R2_ENDPOINT")),
		Region:           aws.String(os.Getenv("R2_DEFAULT_REGION")),
		S3ForcePathStyle: aws.Bool(true),
		Credentials: credentials.NewStaticCredentials(
			os.Getenv("R2_ACCESS_KEY_ID"),
			os.Getenv("R2_SECRET_ACCESS_KEY"),
			"",
		),
	})
	if err != nil {
		log.Printf("Failed to create R2 session: %v", err)
		return err
	}

	R2Session = sess

	return nil
}
