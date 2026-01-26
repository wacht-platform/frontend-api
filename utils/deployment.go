package utils

import (
	"encoding/json"
	"fmt"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/plugin/dbresolver"
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
	if cachedDeployment, found := GetCachedDeployment(host); found {
		return cachedDeployment, nil
	}

	queryResult := new(DeploymentQueryResult)
	rawSQL := `
		SELECT 
			d.*, 
			das.*, 
			dbs.*, 
			dds.*, 
			dr.*, 
			kp.*,
			COALESCE(
				(SELECT json_agg(json_build_object(
					'id', sc.id::text,
					'created_at', to_char(sc.created_at, 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
					'updated_at', to_char(sc.updated_at, 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
					'deployment_id', sc.deployment_id,
					'provider', sc.provider,
					'enabled', sc.enabled
				))
				 FROM deployment_social_connections sc
				 WHERE sc.deployment_id = d.id AND sc.deleted_at IS NULL
				), '[]'::json
			) as social_connections
		FROM deployments d
		LEFT JOIN deployment_auth_settings das ON d.id = das.deployment_id
		LEFT JOIN deployment_b2b_settings dbs ON d.id = dbs.deployment_id
		LEFT JOIN deployment_ui_settings dds ON d.id = dds.deployment_id
		LEFT JOIN deployment_restrictions dr ON d.id = dr.deployment_id
		LEFT JOIN deployment_key_pairs kp ON d.id = kp.deployment_id
		WHERE d.backend_host = ? AND d.deleted_at IS NULL
	`
	err := database.Connection.Clauses(dbresolver.Read).Raw(rawSQL, host).Scan(queryResult).Error

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
	deployment.KepPair = &queryResult.KepPair

	// Cache the deployment before returning
	SetCachedDeployment(host, deployment)

	return deployment, nil
}
