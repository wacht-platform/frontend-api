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
		Scopes:       []string{"users.read", "users.email", "offline.access"},
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
		Scopes:       []string{"name", "email", "openid"},
	},
	"linkedin_oauth": {
		ClientID:     "",
		ClientSecret: "",
		RedirectURI:  "",
		Scopes:       []string{"profile", "email", "openid"},
	},
	"discord_oauth": {
		ClientID:     "",
		ClientSecret: "",
		RedirectURI:  "",
		Scopes:       []string{"identify", "email"},
	},
	"gitlab_oauth": {
		ClientID:     "",
		ClientSecret: "",
		RedirectURI:  "",
		Scopes:       []string{"read_user"},
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

func GetDeploymentOAuthCredentials(deployment *model.Deployment, provider model.SocialConnectionProvider) (*model.OauthCredentials, error) {
	for _, conn := range deployment.SocialConnections {
		if conn.Provider == provider && conn.Enabled && conn.Credentials != nil {
			creds := *conn.Credentials
			if creds.RedirectURI == "" {
				creds.RedirectURI = deployment.FrontendHost + "/sso-callback"
			}
			return &creds, nil
		}
	}

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
