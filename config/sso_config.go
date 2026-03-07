package config

import (
	"fmt"
	"strings"

	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/model"
	"gorm.io/gorm"
	"gorm.io/plugin/dbresolver"
)

func getSSOConfig() map[string]model.OauthCredentials {
	return map[string]model.OauthCredentials{
		"google_oauth": {
			ClientID:     GetEnv("GOOGLE_CLIENT_ID", ""),
			ClientSecret: GetEnv("GOOGLE_CLIENT_SECRET", ""),
			Scopes:       []string{"openid", "email", "profile"},
		},
		// Microsoft OAuth temporarily disabled - unverified credentials
		// "microsoft_oauth": {
		// 	ClientID:     GetEnv("MICROSOFT_CLIENT_ID", ""),
		// 	ClientSecret: GetEnv("MICROSOFT_CLIENT_SECRET", ""),
		// 	Scopes: []string{
		// 		"openid",
		// 		"email",
		// 		"profile",
		// 		"https://graph.microsoft.com/User.Read",
		// 	},
		// },
		"github_oauth": {
			ClientID:     GetEnv("GITHUB_CLIENT_ID", ""),
			ClientSecret: GetEnv("GITHUB_CLIENT_SECRET", ""),
			Scopes:       []string{"user"},
		},
		"linkedin_oauth": {
			ClientID:     GetEnv("LINKEDIN_CLIENT_ID", ""),
			ClientSecret: GetEnv("LINKEDIN_CLIENT_SECRET", ""),
			Scopes:       []string{"profile", "email", "openid"},
		},
		"discord_oauth": {
			ClientID:     GetEnv("DISCORD_CLIENT_ID", ""),
			ClientSecret: GetEnv("DISCORD_CLIENT_SECRET", ""),
			Scopes:       []string{"identify", "email"},
		},
		"gitlab_oauth": {
			ClientID:     GetEnv("GITLAB_CLIENT_ID", ""),
			ClientSecret: GetEnv("GITLAB_CLIENT_SECRET", ""),
			Scopes:       []string{"read_user"},
		},
	}
}

func GetDefaultOAuthCredentials(name string) model.OauthCredentials {
	return getSSOConfig()[name]
}

func GetOAuthCredentialsWithRedirectURI(name string, frontendHost string) model.OauthCredentials {
	creds := getSSOConfig()[name]
	return creds
}

func GetDeploymentOAuthCredentials(
	deployment *model.Deployment,
	provider model.SocialConnectionProvider,
) (*model.OauthCredentials, error) {
	if deployment == nil {
		return nil, fmt.Errorf("deployment is required")
	}

	var socialConnection model.DeploymentSocialConnection
	err := database.Connection.
		Clauses(dbresolver.Read).
		Where(
			"deployment_id = ? AND provider = ? AND enabled = ? AND deleted_at IS NULL",
			deployment.ID,
			provider,
			true,
		).
		First(&socialConnection).
		Error
	if err == nil && socialConnection.Credentials != nil {
		creds := *socialConnection.Credentials
		hasClientID := strings.TrimSpace(creds.ClientID) != ""
		hasClientSecret := strings.TrimSpace(creds.ClientSecret) != ""

		if hasClientID && hasClientSecret {
			if len(creds.Scopes) == 0 {
				// Keep sensible defaults when custom credentials omit scopes.
				creds.Scopes = GetDefaultOAuthCredentials(string(provider)).Scopes
			}
			return &creds, nil
		}

		if deployment.Mode == model.DeploymentModeProduction {
			if !hasClientID {
				return nil, fmt.Errorf(
					"oauth credentials for provider %s are missing client_id",
					provider,
				)
			}
			return nil, fmt.Errorf(
				"oauth credentials for provider %s are missing client_secret",
				provider,
			)
		}
	}
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf(
			"failed to load OAuth credentials for provider %s: %w",
			provider,
			err,
		)
	}

	if deployment.Mode != model.DeploymentModeProduction {
		defaultCreds := GetDefaultOAuthCredentials(string(provider))
		if defaultCreds.ClientID != "" {
			return &defaultCreds, nil
		}
	}

	return nil, fmt.Errorf("no OAuth credentials found for provider %s", provider)
}
