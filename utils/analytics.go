package utils

import (
	"log"

	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/service"
)

// signinGeo reuses the country/device already resolved on the Signin during
// CreateSignin, so analytics doesn't re-run a GeoIP lookup or UA parse.
func signinGeo(s *model.Signin) (country, device *string) {
	if s == nil {
		return
	}
	if s.Country != "" {
		c := s.Country
		country = &c
	}
	if s.Device != "" {
		d := s.Device
		device = &d
	}
	return
}

func PublishSignInEvent(deploymentID uint64, user *model.User, authMethod string, identifier *string, signin *model.Signin, c fiber.Ctx) {
	natsService := service.GetNATS()
	ipAddress := c.IP()
	country, device := signinGeo(signin)

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
			country,
			device,
		); err != nil {
			log.Printf("[ANALYTICS ERROR] Failed to publish signin event to NATS: %v", err)
			return
		}

		log.Printf("[ANALYTICS] Published signin event for user:%d (deployment:%d)", user.ID, deploymentID)
	}()
}

func PublishSignUpEvent(deploymentID uint64, user *model.User, authMethod string, identifier *string, signin *model.Signin, c fiber.Ctx) {
	natsService := service.GetNATS()

	// Index the freshly-created user for search. This runs post-commit for every
	// interactive signup flow (password, oauth, enterprise SSO, OIDC), so new users
	// are searchable immediately instead of only after a later profile/membership edit.
	if err := natsService.PublishSearchUserSync(user.ID); err != nil {
		log.Printf("[search] failed to enqueue sync for user %d: %v", user.ID, err)
	}

	ipAddress := c.IP()
	country, device := signinGeo(signin)

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
			country,
			device,
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
			nil,
			nil,
		); err != nil {
			log.Printf("[ANALYTICS ERROR] Failed to publish workspace_created event to NATS: %v", err)
			return
		}

		log.Printf("[ANALYTICS] Published workspace_created event (deployment:%d)", deploymentID)
	}()
}
