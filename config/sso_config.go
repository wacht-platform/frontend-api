package config

import (
	"fmt"

	"github.com/ilabs/wacht-fe/model"
)

func getSSOConfig() map[string]model.OauthCredentials {
	return map[string]model.OauthCredentials{
		"google_oauth": {
			ClientID:     GetEnv("GOOGLE_CLIENT_ID", ""),
			ClientSecret: GetEnv("GOOGLE_CLIENT_SECRET", ""),
			Scopes:       []string{"openid", "email", "profile"},
		},
		"microsoft_oauth": {
			ClientID:     GetEnv("MICROSOFT_CLIENT_ID", ""),
			ClientSecret: GetEnv("MICROSOFT_CLIENT_SECRET", ""),
			Scopes: []string{
				"openid",
				"email",
				"profile",
				"https://graph.microsoft.com/User.Read",
			},
		},
		"github_oauth": {
			ClientID:     GetEnv("GITHUB_CLIENT_ID", ""),
			ClientSecret: GetEnv("GITHUB_CLIENT_SECRET", ""),
			Scopes:       []string{"user"},
		},
		"x_oauth": {
			ClientID:     GetEnv("X_CLIENT_ID", ""),
			ClientSecret: GetEnv("X_CLIENT_SECRET", ""),
			Scopes:       []string{"users.read", "users.email", "offline.access"},
		},
		"facebook_oauth": {
			ClientID:     GetEnv("FACEBOOK_CLIENT_ID", ""),
			ClientSecret: GetEnv("FACEBOOK_CLIENT_SECRET", ""),
			Scopes:       []string{"email"},
		},
		"apple_oauth": {
			ClientID:     GetEnv("APPLE_CLIENT_ID", ""),
			ClientSecret: GetEnv("APPLE_CLIENT_SECRET", ""),
			Scopes:       []string{"name", "email", "openid"},
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

func GetDeploymentOAuthCredentials(deployment *model.Deployment, provider model.SocialConnectionProvider) (*model.OauthCredentials, error) {
	for _, conn := range deployment.SocialConnections {
		if conn.Provider == provider && conn.Enabled && conn.Credentials != nil {
			creds := *conn.Credentials
			return &creds, nil
		}
	}

	if deployment.Mode != model.DeploymentModeProduction {
		defaultCreds := GetDefaultOAuthCredentials(string(provider))
		if defaultCreds.ClientID != "" {
			return &defaultCreds, nil
		}
	}

	return nil, fmt.Errorf("no OAuth credentials found for provider %s", provider)
}
