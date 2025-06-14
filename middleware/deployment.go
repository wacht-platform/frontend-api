package middleware

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"github.com/redis/go-redis/v9"
)

func SetDeploymentMiddleware(c *fiber.Ctx) error {
	host := c.Hostname()
	path := c.Path()

	if strings.HasPrefix(path, "/.well") {
		return c.Next()
	}

	val, err := database.Redis.Get(context.Background(), "deployment:"+host).Result()
	if err == nil {
		deployment := new(model.Deployment)
		if json.Unmarshal([]byte(val), &deployment) == nil {
			keyPairVal, err := database.Redis.Get(context.Background(), "keypair:"+host).Result()
			if err == nil {
				keyPair := new(model.DeploymentKeyPair)
				if json.Unmarshal([]byte(keyPairVal), &keyPair) == nil {
					deployment.KepPair = *keyPair
				}
			}
			c.Locals("deployment", *deployment)
			return c.Next()
		}
	} else if err != redis.Nil {
		return c.Status(500).JSON(fiber.Map{"message": "Redis error"})
	}

	deployment := new(model.Deployment)
	rawSQL := `
		SELECT d.*, das.*, dbs.*, dds.*, dr.*, det.*, dst.*, json_agg(sc) as social_connections
		FROM deployments d
		LEFT JOIN deployment_auth_settings das ON d.id = das.deployment_id
		LEFT JOIN deployment_b2b_settings dbs ON d.id = dbs.deployment_id
		LEFT JOIN deployment_ui_settings dds ON d.id = dds.deployment_id
		LEFT JOIN deployment_restrictions dr ON d.id = dr.deployment_id
		LEFT JOIN deployment_email_templates det ON d.id = det.deployment_id
		LEFT JOIN deployment_sms_templates dst ON d.id = dst.deployment_id
		LEFT JOIN deployment_social_connections sc ON d.id = sc.deployment_id
		WHERE d.backend_host = ?
		GROUP BY d.id, das.id, dbs.id, dds.id, dr.id, det.id, dst.id
	`
	err = database.Connection.Raw(rawSQL, host).Scan(&deployment).Error

	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"message": "Deployment not found",
		})
	}

	deployment.LoadKepPair(database.Connection)

	keyPairJSON, _ := json.Marshal(deployment.KepPair)
	deployment.KepPair = model.DeploymentKeyPair{}
	deploymentJSON, _ := json.Marshal(deployment)

	database.Redis.Set(context.Background(), "deployment:"+host, deploymentJSON, 1*time.Hour)
	database.Redis.Set(context.Background(), "keypair:"+host, keyPairJSON, 1*time.Hour)

	keyPair := new(model.DeploymentKeyPair)
	json.Unmarshal(keyPairJSON, keyPair)
	deployment.KepPair = *keyPair

	c.Locals("deployment", *deployment)

	return c.Next()
}
