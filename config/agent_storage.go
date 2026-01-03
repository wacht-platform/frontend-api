package config

import (
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
)

var AgentStorageSession *session.Session

func initAgentStorageSession() error {
	gatewayURL := os.Getenv("AGENT_STORAGE_GATEWAY_URL")
	if gatewayURL == "" {
		log.Println("AGENT_STORAGE_GATEWAY_URL not set, agent storage disabled")
		return nil
	}

	sess, err := session.NewSession(&aws.Config{
		Endpoint:         aws.String(gatewayURL),
		Region:           aws.String("us-east-1"),
		S3ForcePathStyle: aws.Bool(true),
		Credentials: credentials.NewStaticCredentials(
			os.Getenv("AGENT_STORAGE_ACCESS_KEY"),
			os.Getenv("AGENT_STORAGE_SECRET_KEY"),
			"",
		),
	})
	if err != nil {
		log.Printf("Failed to create agent storage session: %v", err)
		return err
	}

	AgentStorageSession = sess
	log.Printf("Agent storage session initialized: %s", gatewayURL)

	return nil
}
