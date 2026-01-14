package utils

import (
	"log"

	"github.com/ilabs/wacht-fe/service"
)

func PublishWebhookEvent(deploymentID uint64, eventType string, entityID uint64, entityType string) {
	natsService := service.GetNATS()

	go func() {
		payload := map[string]interface{}{
			"entity_id":   entityID,
			"entity_type": entityType,
		}

		if err := natsService.PublishWebhookEvent(deploymentID, eventType, payload); err != nil {
			log.Printf("[WEBHOOK ERROR] Failed to publish event '%s' to NATS: %v", eventType, err)
			return
		}

		log.Printf("[WEBHOOK] Published event '%s' for %s:%d (deployment:%d)",
			eventType, entityType, entityID, deploymentID)
	}()
}
