package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
)

type DeploymentQueryResult struct {
	model.Deployment
	AuthSettings      model.DeploymentAuthSettings `gorm:"embedded"`
	B2BSettings       model.DeploymentB2bSettings  `gorm:"embedded"`
	UISettings        model.DeploymentUISettings   `gorm:"embedded"`
	Restrictions      model.DeploymentRestrictions `gorm:"embedded"`
	SocialConnections json.RawMessage              `gorm:"column:social_connections"`
	KepPair           model.DeploymentKeyPair      `gorm:"embedded"`
}

func GetDeploymentByHost(host string) (*model.Deployment, error) {
	resp, err := http.Get(os.Getenv("CACHE_WORKER") + "?q=" + host)
	if err == nil && resp.StatusCode == 200 {
		deployment := new(model.Deployment)
		if err := GetFromCache(resp, deployment); err == nil {
			return deployment, nil
		}
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
		SELECT d.*, das.*, dbs.*, dds.*, dr.*, sca.social_connections, kp.*
		FROM deployments d
		LEFT JOIN deployment_auth_settings das ON d.id = das.deployment_id
		LEFT JOIN deployment_b2b_settings dbs ON d.id = dbs.deployment_id
		LEFT JOIN deployment_ui_settings dds ON d.id = dds.deployment_id
		LEFT JOIN deployment_restrictions dr ON d.id = dr.deployment_id
		LEFT JOIN deployment_key_pairs kp ON d.id = kp.deployment_id
		LEFT JOIN social_connections_agg sca ON d.id = sca.deployment_id
		WHERE d.backend_host = ? AND d.deleted_at IS NULL
	`
	err = database.Connection.Raw(rawSQL, host).Scan(queryResult).Error

	if err != nil || queryResult.ID == 0 {
		return nil, fmt.Errorf("deployment not found")
	}

	deployment := &queryResult.Deployment
	deployment.AuthSettings = queryResult.AuthSettings
	deployment.B2BSettings = queryResult.B2BSettings
	deployment.UISettings = queryResult.UISettings
	deployment.Restrictions = queryResult.Restrictions

	if queryResult.SocialConnections != nil && string(queryResult.SocialConnections) != "null" {
		json.Unmarshal(queryResult.SocialConnections, &deployment.SocialConnections)
	} else {
		deployment.SocialConnections = []model.DeploymentSocialConnection{}
	}
	deployment.KepPair = queryResult.KepPair

	go setDeploymentCache(*deployment)

	return deployment, nil
}

func setDeploymentCache(deployment model.Deployment) {
	err := SetToCache(deployment.BackendHost, deployment, 86400)
	if err != nil {
		log.Println("Error setting deployment cache: ", err)
	}
}
