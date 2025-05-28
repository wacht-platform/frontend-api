package config

import (
	"fmt"

	"github.com/ilabs/wacht-fe/model"
)

var ssoConfig = map[string]model.OauthCredentials{
	"google_oauth": {
		ClientID:     "",
		ClientSecret: "",
		RedirectURI:  "",
		Scopes:       []string{"openid", "email", "profile"},
	},
	"microsoft_oauth": {
		ClientID:     "",
		ClientSecret: "",
		RedirectURI:  "",
		Scopes: []string{
			"openid",
			"email",
			"profile",
			"https://graph.microsoft.com/User.Read",
		},
	},
	"github_oauth": {
		ClientID:     "",
		ClientSecret: "",
		RedirectURI:  "",
		Scopes:       []string{"user"},
	},
	"x_oauth": {
		ClientID:     "",
		ClientSecret: "",
		RedirectURI:  "",
		Scopes:       []string{"users.read", "offline.access"},
	},
	"facebook_oauth": {
		ClientID:     "",
		ClientSecret: "",
		RedirectURI:  "",
		Scopes:       []string{"email"},
	},
	"apple_oauth": {
		ClientID:     "",
		ClientSecret: "",
		RedirectURI:  "",
		Scopes:       []string{"email"},
	},
	"linkedin_oauth": {
		ClientID:     "",
		ClientSecret: "",
		RedirectURI:  "",
		Scopes:       []string{"r_liteprofile", "r_emailaddress"},
	},
	"discord_oauth": {
		ClientID:     "",
		ClientSecret: "",
		RedirectURI:  "",
		Scopes:       []string{"identify", "email"},
	},
}

func GetDefaultOAuthCredentials(name string) model.OauthCredentials {
	return ssoConfig[name]
}

func GetOAuthCredentialsWithRedirectURI(name string, frontendHost string) model.OauthCredentials {
	creds := ssoConfig[name]
	if creds.RedirectURI == "" {
		creds.RedirectURI = frontendHost + "/sso-callback"
	}
	return creds
}

// GetDeploymentOAuthCredentials retrieves OAuth credentials for a specific deployment and provider
func GetDeploymentOAuthCredentials(deployment *model.Deployment, provider model.SocialConnectionProvider) (*model.OauthCredentials, error) {
	// First, try to find deployment-specific credentials
	for _, conn := range deployment.SocialConnections {
		if conn.Provider == provider && conn.Enabled && conn.Credentials != nil {
			// Use deployment-specific credentials
			creds := *conn.Credentials
			if creds.RedirectURI == "" {
				creds.RedirectURI = deployment.FrontendHost + "/sso-callback"
			}
			return &creds, nil
		}
	}

	// Fallback to default credentials for development/staging
	if deployment.Mode != model.DeploymentModeProduction {
		defaultCreds := GetDefaultOAuthCredentials(string(provider))
		if defaultCreds.ClientID != "" {
			if defaultCreds.RedirectURI == "" {
				defaultCreds.RedirectURI = deployment.FrontendHost + "/sso-callback"
			}
			return &defaultCreds, nil
		}
	}

	return nil, fmt.Errorf("no OAuth credentials found for provider %s", provider)
}
