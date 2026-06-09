package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/wacht-platform/frontend-api/config"
)

type S3Service struct {
	client *s3.S3
}

func NewS3Service() *S3Service {
	return &S3Service{
		client: s3.New(config.R2Session),
	}
}

func (s *S3Service) UploadFromURL(key, sourceURL string) (string, error) {
	resp, err := http.Get(sourceURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download image from %s: status %d", sourceURL, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return s.UploadToCdn(key, bytes.NewReader(data))
}

func (s *S3Service) UploadToCdn(key string, file io.ReadSeeker) (string, error) {
	_, err := s.client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(os.Getenv("R2_CDN_BUCKET")),
		Key:    aws.String(key),
		Body:   file,
	})

	if err != nil {
		return "", err
	}

	fileURL := fmt.Sprintf("https://cdn.wacht.services/%s", key)

	type PurgeRequest struct {
		Files []string `json:"files"`
	}

	purgeReq := PurgeRequest{
		Files: []string{fileURL},
	}

	reqBody, err := json.Marshal(purgeReq)
	if err != nil {
		return fileURL, err
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/purge_cache", os.Getenv("CLOUDFLARE_ZONE_ID")),
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return fileURL, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", os.Getenv("CLOUDFLARE_API_KEY")))

	client := &http.Client{}
	_, err = client.Do(req)

	return fileURL, err
}
