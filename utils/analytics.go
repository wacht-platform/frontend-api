package utils

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/service"
)

func PublishSignInEvent(deploymentID uint64, user *model.User, authMethod string, c *fiber.Ctx) {
	natsService, err := service.NewNatsService()
	if err != nil {
		log.Printf("[ANALYTICS ERROR] Failed to create NATS service for signin event: %v", err)
		return
	}

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

		var userEmail *string
		if user.PrimaryEmailAddressID != nil {
			for _, email := range user.UserEmailAddresses {
				if email.ID == *user.PrimaryEmailAddressID {
					userEmail = &email.EmailAddress
					break
				}
			}
		}

		ipAddress := c.IP()

		userID := user.ID
		if err := natsService.PublishAnalyticsEvent(
			deploymentID,
			&userID,
			"signin",
			userName,
			userEmail,
			&authMethod,
			&ipAddress,
		); err != nil {
			log.Printf("[ANALYTICS ERROR] Failed to publish signin event to NATS: %v", err)
			return
		}

		log.Printf("[ANALYTICS] Published signin event for user:%d (deployment:%d)", user.ID, deploymentID)
	}()
}

func PublishSignUpEvent(deploymentID uint64, user *model.User, authMethod string, c *fiber.Ctx) {
	natsService, err := service.NewNatsService()
	if err != nil {
		log.Printf("[ANALYTICS ERROR] Failed to create NATS service for signup event: %v", err)
		return
	}

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

		var userEmail *string
		if user.PrimaryEmailAddressID != nil {
			for _, email := range user.UserEmailAddresses {
				if email.ID == *user.PrimaryEmailAddressID {
					userEmail = &email.EmailAddress
					break
				}
			}
		}

		ipAddress := c.IP()

		userID := user.ID
		if err := natsService.PublishAnalyticsEvent(
			deploymentID,
			&userID,
			"signup",
			userName,
			userEmail,
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
	natsService, err := service.NewNatsService()
	if err != nil {
		log.Printf("[ANALYTICS ERROR] Failed to create NATS service for organization_created event: %v", err)
		return
	}

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
	natsService, err := service.NewNatsService()
	if err != nil {
		log.Printf("[ANALYTICS ERROR] Failed to create NATS service for workspace_created event: %v", err)
		return
	}

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
