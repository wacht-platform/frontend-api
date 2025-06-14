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

type DeploymentQueryResult struct {
	model.Deployment
	AuthSettings      model.DeploymentAuthSettings  `gorm:"embedded"`
	B2BSettings       model.DeploymentB2bSettings   `gorm:"embedded"`
	UISettings        model.DeploymentUISettings    `gorm:"embedded"`
	Restrictions      model.DeploymentRestrictions  `gorm:"embedded"`
	EmailTemplates    model.DeploymentEmailTemplate `gorm:"embedded"`
	SmsTemplates      model.DeploymentSmsTemplate   `gorm:"embedded"`
	SocialConnections json.RawMessage               `gorm:"column:social_connections"`
	KepPair           model.DeploymentKeyPair       `gorm:"embedded"`
}

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

	queryResult := new(DeploymentQueryResult)
	rawSQL := `
		WITH social_connections_agg AS (
			SELECT
				deployment_id,
				json_agg(sc) as social_connections
			FROM deployment_social_connections sc
			GROUP BY deployment_id
		)
		SELECT d.*, das.*, dbs.*, dds.*, dr.*, det.*, dst.*, sca.social_connections, kp.*
		FROM deployments d
		LEFT JOIN deployment_auth_settings das ON d.id = das.deployment_id
		LEFT JOIN deployment_b2b_settings dbs ON d.id = dbs.deployment_id
		LEFT JOIN deployment_ui_settings dds ON d.id = dds.deployment_id
		LEFT JOIN deployment_restrictions dr ON d.id = dr.deployment_id
		LEFT JOIN deployment_email_templates det ON d.id = det.deployment_id
		LEFT JOIN deployment_sms_templates dst ON d.id = dst.deployment_id
		LEFT JOIN deployment_key_pairs kp ON d.id = kp.deployment_id
		LEFT JOIN social_connections_agg sca ON d.id = sca.deployment_id
		WHERE d.backend_host = ?
	`
	err = database.Connection.Raw(rawSQL, host).Scan(queryResult).Error

	if err != nil || queryResult.ID == 0 {
		return c.Status(404).JSON(fiber.Map{"message": "Deployment not found"})
	}

	deployment := &queryResult.Deployment
	deployment.AuthSettings = queryResult.AuthSettings
	deployment.B2BSettings = queryResult.B2BSettings
	deployment.UISettings = queryResult.UISettings
	deployment.Restrictions = queryResult.Restrictions
	deployment.EmailTemplates = &queryResult.EmailTemplates
	deployment.SmsTemplates = &queryResult.SmsTemplates

	if queryResult.SocialConnections != nil && string(queryResult.SocialConnections) != "null" {
		json.Unmarshal(queryResult.SocialConnections, &deployment.SocialConnections)
	}
	deployment.KepPair = queryResult.KepPair

	keyPairJSON, _ := json.Marshal(deployment.KepPair)
	deploymentToCache := *deployment
	deploymentToCache.KepPair = model.DeploymentKeyPair{}
	deploymentJSON, _ := json.Marshal(deploymentToCache)

	database.Redis.Set(context.Background(), "deployment:"+host, deploymentJSON, 1*time.Hour)
	database.Redis.Set(context.Background(), "keypair:"+host, keyPairJSON, 1*time.Hour)

	c.Locals("deployment", *deployment)

	return c.Next()
}
