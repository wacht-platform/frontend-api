package utils

import (
	"log"

	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/service"
)

func PublishSignInEvent(deploymentID uint64, user *model.User, authMethod string, identifier *string, c fiber.Ctx) {
	natsService := service.GetNATS()
	ipAddress := c.IP()

	go func() {
		var userName *string
		if user.FirstName != "" && user.LastName != "" {
			fullName := user.FirstName + " " + user.LastName
			userName = &fullName
		} else if user.FirstName != "" {
			userName = &user.FirstName
		} else if user.LastName != "" {
			userName = &user.LastName
		}

		userID := user.ID
		if err := natsService.PublishAnalyticsEvent(
			deploymentID,
			&userID,
			"signin",
			userName,
			identifier,
			&authMethod,
			&ipAddress,
		); err != nil {
			log.Printf("[ANALYTICS ERROR] Failed to publish signin event to NATS: %v", err)
			return
		}

		log.Printf("[ANALYTICS] Published signin event for user:%d (deployment:%d)", user.ID, deploymentID)
	}()
}

func PublishSignUpEvent(deploymentID uint64, user *model.User, authMethod string, identifier *string, c fiber.Ctx) {
	natsService := service.GetNATS()
	ipAddress := c.IP()

	go func() {
		var userName *string
		if user.FirstName != "" && user.LastName != "" {
			fullName := user.FirstName + " " + user.LastName
			userName = &fullName
		} else if user.FirstName != "" {
			userName = &user.FirstName
		} else if user.LastName != "" {
			userName = &user.LastName
		}

		userID := user.ID
		if err := natsService.PublishAnalyticsEvent(
			deploymentID,
			&userID,
			"signup",
			userName,
			identifier,
			&authMethod,
			&ipAddress,
		); err != nil {
			log.Printf("[ANALYTICS ERROR] Failed to publish signup event to NATS: %v", err)
			return
		}

		log.Printf("[ANALYTICS] Published signup event for user:%d (deployment:%d)", user.ID, deploymentID)
	}()
}

func PublishOrganizationCreatedEvent(deploymentID uint64, userID *uint64) {
	natsService := service.GetNATS()

	go func() {
		if err := natsService.PublishAnalyticsEvent(
			deploymentID,
			userID,
			"organization_created",
			nil,
			nil,
			nil,
			nil,
		); err != nil {
			log.Printf("[ANALYTICS ERROR] Failed to publish organization_created event to NATS: %v", err)
			return
		}

		log.Printf("[ANALYTICS] Published organization_created event (deployment:%d)", deploymentID)
	}()
}

func PublishWorkspaceCreatedEvent(deploymentID uint64, userID *uint64) {
	natsService := service.GetNATS()

	go func() {
		if err := natsService.PublishAnalyticsEvent(
			deploymentID,
			userID,
			"workspace_created",
			nil,
			nil,
			nil,
			nil,
		); err != nil {
			log.Printf("[ANALYTICS ERROR] Failed to publish workspace_created event to NATS: %v", err)
			return
		}

		log.Printf("[ANALYTICS] Published workspace_created event (deployment:%d)", deploymentID)
	}()
}
