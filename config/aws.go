package config

import (
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
)

var AwsSession *session.Session

func InitAwsSession() error {
	sess, err := session.NewSession(&aws.Config{
		Endpoint: aws.String(os.Getenv("R2_ENDPOINT")),
		Region:   aws.String(os.Getenv("R2_DEFAULT_REGION")),
		Credentials: credentials.NewStaticCredentials(
			os.Getenv("R2_ACCESS_KEY_ID"),
			os.Getenv("R2_SECRET_ACCESS_KEY"),
			"",
		),
	})
	if err != nil {
		log.Printf("Failed to create AWS session: %v", err)
		return err
	}

	AwsSession = sess

	return nil
}
