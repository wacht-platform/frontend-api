package agent

import (
	"fmt"
	"io"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/handler"
)

func (h *Handler) ServeFile(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentToken(c)
	if err != nil {
		return err
	}

	contextIDStr := c.Params("context_id")
	contextID, err := strconv.ParseUint(contextIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid context ID")
	}

	filename := c.Params("filename")
	if filename == "" {
		return handler.SendBadRequest(c, nil, "Filename required")
	}

	deployment := handler.GetDeployment(c)

	// Verify context access (context_group check happens in GetContext)
	_, err = h.service.GetContext(deployment.ID, contextGroup, contextID)
	if err != nil {
		return handler.SendNotFound(c, nil, "Context not found or access denied")
	}

	if config.AgentStorageSession == nil {
		return handler.SendInternalServerError(c, nil, "File storage not configured")
	}

	s3Client := s3.New(config.AgentStorageSession)
	bucket := "wacht-agents"

	key := fmt.Sprintf("%d/persistent/%d/uploads/%s",
		deployment.ID,
		contextID,
		filename,
	)

	result, err := s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return handler.SendNotFound(c, nil, "File not found")
	}
	defer result.Body.Close()

	if result.ContentType != nil {
		c.Set("Content-Type", *result.ContentType)
	}
	if result.ContentLength != nil {
		c.Set("Content-Length", strconv.FormatInt(*result.ContentLength, 10))
	}

	c.Set("Cache-Control", "public, max-age=31536000")

	body, err := io.ReadAll(result.Body)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to read file")
	}

	return c.Send(body)
}
