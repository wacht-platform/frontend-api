package utils

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/model"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/linkedin"
	"golang.org/x/oauth2/microsoft"
)

type OAuthUser struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	ImageUrl  string `json:"image_url"`
}

func GenerateVerificationUrl(
	ssoProvider model.SocialConnectionProvider,
	attempt model.SignInAttempt,
) string {
	url := ""

	defcred := config.GetDefaultOAuthCredentials(string(ssoProvider))

	conf := &oauth2.Config{
		ClientID:     defcred.ClientID,
		ClientSecret: defcred.ClientSecret,
		RedirectURL:  defcred.RedirectURI,
		Scopes:       defcred.Scopes,
	}

	switch ssoProvider {
	case model.SocialConnectionProviderX:
		conf.Endpoint = oauth2.Endpoint{
			AuthURL:  "https://x.com/i/oauth2/authorize",
			TokenURL: "https://x.com/i/oauth2/token",
		}
		url = conf.AuthCodeURL(
			strconv.FormatUint(uint64(attempt.ID), 10),
		)
	case model.SocialConnectionProviderGitHub:
		conf.Endpoint = github.Endpoint
		url = conf.AuthCodeURL(
			strconv.FormatUint(uint64(attempt.ID), 10),
		)
	case model.SocialConnectionProviderGitLab:
	case model.SocialConnectionProviderGoogle:
		conf.Endpoint = google.Endpoint
		url = conf.AuthCodeURL(
			strconv.FormatUint(uint64(attempt.ID), 10),
		)
	case model.SocialConnectionProviderFacebook:
	case model.SocialConnectionProviderMicrosoft:
		conf.Endpoint = microsoft.AzureADEndpoint("")
		url = conf.AuthCodeURL(
			strconv.FormatUint(uint64(attempt.ID), 10),
		)
	case model.SocialConnectionProviderLinkedIn:
	case model.SocialConnectionProviderDiscord:
	}

	return url
}

func GenerateVerificationUrlWithRedirect(
	ssoProvider model.SocialConnectionProvider,
	attempt model.SignInAttempt,
	frontendHost string,
	customRedirectURI string,
) string {
	url := ""

	cred := config.GetOAuthCredentialsWithRedirectURI(string(ssoProvider), frontendHost)

	conf := &oauth2.Config{
		ClientID:     cred.ClientID,
		ClientSecret: cred.ClientSecret,
		RedirectURL:  cred.RedirectURI,
		Scopes:       cred.Scopes,
	}

	// Add custom redirect_uri as a parameter if provided
	state := strconv.FormatUint(uint64(attempt.ID), 10)
	if customRedirectURI != "" {
		state += ":" + customRedirectURI
	}

	switch ssoProvider {
	case model.SocialConnectionProviderX:
		conf.Endpoint = oauth2.Endpoint{
			AuthURL:  "https://x.com/i/oauth2/authorize",
			TokenURL: "https://x.com/i/oauth2/token",
		}
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderGitHub:
		conf.Endpoint = github.Endpoint
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderGitLab:
	case model.SocialConnectionProviderGoogle:
		conf.Endpoint = google.Endpoint
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderFacebook:
	case model.SocialConnectionProviderMicrosoft:
		conf.Endpoint = microsoft.AzureADEndpoint("")
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderLinkedIn:
	case model.SocialConnectionProviderDiscord:
	}

	return url
}

func GenerateVerificationUrlForDeployment(
	ssoProvider model.SocialConnectionProvider,
	attempt model.SignInAttempt,
	deployment *model.Deployment,
	customRedirectURI string,
) (string, error) {
	url := ""

	// Get deployment-specific OAuth config
	conf, err := getOAuthConfigForDeployment(ssoProvider, deployment)
	if err != nil {
		return "", err
	}

	// Add custom redirect_uri as a parameter if provided
	state := strconv.FormatUint(uint64(attempt.ID), 10)
	if customRedirectURI != "" {
		state += ":" + customRedirectURI
	}

	switch ssoProvider {
	case model.SocialConnectionProviderX:
		conf.Endpoint = oauth2.Endpoint{
			AuthURL:  "https://x.com/i/oauth2/authorize",
			TokenURL: "https://x.com/i/oauth2/token",
		}
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderGitHub:
		conf.Endpoint = github.Endpoint
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderGitLab:
	case model.SocialConnectionProviderGoogle:
		conf.Endpoint = google.Endpoint
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderFacebook:
	case model.SocialConnectionProviderMicrosoft:
		conf.Endpoint = microsoft.AzureADEndpoint("")
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderLinkedIn:
	case model.SocialConnectionProviderDiscord:
	}

	return url, nil
}

func getOAuthConfigForDeployment(
	provider model.SocialConnectionProvider,
	deployment *model.Deployment,
) (*oauth2.Config, error) {
	cred, err := config.GetDeploymentOAuthCredentials(deployment, provider)
	if err != nil {
		return nil, err
	}

	conf := &oauth2.Config{
		ClientID:     cred.ClientID,
		ClientSecret: cred.ClientSecret,
		RedirectURL:  cred.RedirectURI,
		Scopes:       cred.Scopes,
	}

	switch provider {
	case model.SocialConnectionProviderGitHub:
		conf.Endpoint = github.Endpoint
	case model.SocialConnectionProviderGoogle:
		conf.Endpoint = google.Endpoint
	case model.SocialConnectionProviderMicrosoft:
		conf.Endpoint = microsoft.AzureADEndpoint("")
	case model.SocialConnectionProviderFacebook:
		conf.Endpoint = facebook.Endpoint
	case model.SocialConnectionProviderLinkedIn:
		conf.Endpoint = linkedin.Endpoint
	case model.SocialConnectionProviderX:
		conf.Endpoint = oauth2.Endpoint{
			AuthURL:  "https://x.com/i/oauth2/authorize",
			TokenURL: "https://x.com/i/oauth2/token",
		}
	case model.SocialConnectionProviderApple:
		conf.Endpoint = oauth2.Endpoint{
			AuthURL:  "https://appleid.apple.com/auth/authorize",
			TokenURL: "https://appleid.apple.com/auth/token",
		}
	case model.SocialConnectionProviderDiscord:
		conf.Endpoint = oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		}
	}

	return conf, nil
}

func ExchangeTokenForUser(
	token *oauth2.Token,
	ssoProvider model.SocialConnectionProvider,
) (*OAuthUser, error) {
	switch ssoProvider {
	case model.SocialConnectionProviderX:
	case model.SocialConnectionProviderGitHub:
		req, err := http.NewRequest(
			"GET",
			"https://api.github.com/user",
			nil,
		)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var res map[string]any

		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return nil, err
		}

		namesplit := strings.Split(res["name"].(string), " ")

		firstName := namesplit[0]
		var lastName string

		if len(namesplit) > 1 {
			lastName = namesplit[1]
		}

		req, err = http.NewRequest(
			"GET",
			"https://api.github.com/user/emails",
			nil,
		)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var emails []map[string]any

		if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
			return nil, err
		}

		for _, email := range emails {
			if email["primary"].(bool) {
				return &OAuthUser{
					FirstName: firstName,
					LastName:  lastName,
					Email:     email["email"].(string),
				}, nil
			}
		}
	case model.SocialConnectionProviderGitLab:
	case model.SocialConnectionProviderGoogle:
		req, err := http.NewRequest(
			"GET",
			"https://www.googleapis.com/oauth2/v3/userinfo",
			nil,
		)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var res map[string]any

		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return nil, err
		}
		return &OAuthUser{
			FirstName: res["given_name"].(string),
			LastName:  res["family_name"].(string),
			Email:     res["email"].(string),
		}, nil
	case model.SocialConnectionProviderFacebook:
	case model.SocialConnectionProviderMicrosoft:
		req, err := http.NewRequest(
			"GET",
			"https://graph.microsoft.com/v1.0/me",
			nil,
		)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var res map[string]any

		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return nil, err
		}

		return &OAuthUser{
			FirstName: res["givenName"].(string),
			LastName:  res["surname"].(string),
			Email:     res["mail"].(string),
		}, nil
	case model.SocialConnectionProviderLinkedIn:
	case model.SocialConnectionProviderDiscord:
	}
	return nil, nil
}
