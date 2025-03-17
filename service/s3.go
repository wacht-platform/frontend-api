package service

import (
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/ilabs/wacht-fe/config"
)

type S3Service struct {
	client *s3.S3
}

func NewS3Service() *S3Service {
	return &S3Service{
		client: s3.New(config.AwsSession),
	}
}

func (s *S3Service) UploadFile(bucket string, key string, file io.ReadSeeker) error {
	_, err := s.client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   file,
	})
	return err
}
