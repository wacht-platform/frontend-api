package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
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

func GenerateVerificationUrlForDeployment(
	ssoProvider model.SocialConnectionProvider,
	attempt model.SignInAttempt,
	deployment *model.Deployment,
	customRedirectURI string,
	keypair model.DeploymentKeyPair,
) (string, error) {
	url := ""

	conf, err := GetOAuthConfigForDeployment(ssoProvider, deployment, customRedirectURI)
	if err != nil {
		return "", err
	}

	fullRedirectURI := fmt.Sprintf("https://%s/sso-callback", deployment.FrontendHost)
	if customRedirectURI != "" {
		fullRedirectURI = fmt.Sprintf("%s?redirect_uri=%s", fullRedirectURI, customRedirectURI)
	}

	secret := GetOAuthStateSecret(deployment.ID, keypair.PrivateKey)
	stateData := OAuthStateData{
		Action:      "sign_in",
		AttemptID:   &attempt.ID,
		RedirectURI: fullRedirectURI,
	}
	state, err := GenerateOAuthState(stateData, secret)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
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
		conf.Endpoint = config.GitLabOAuthEndpoint
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderGoogle:
		conf.Endpoint = google.Endpoint
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderFacebook:
		conf.Endpoint = facebook.Endpoint
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderMicrosoft:
		conf.Endpoint = microsoft.AzureADEndpoint("")
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderLinkedIn:
		conf.Endpoint = linkedin.Endpoint
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderDiscord:
		conf.Endpoint = config.DiscordOAuthEndpoint
		url = conf.AuthCodeURL(state)
	case model.SocialConnectionProviderApple:
		conf.Endpoint = config.AppleOAuthEndpoint
		url = conf.AuthCodeURL(state)
	}

	return url, nil
}

func GetOAuthConfigForDeployment(
	provider model.SocialConnectionProvider,
	deployment *model.Deployment,
	customRedirectURI string,
) (*oauth2.Config, error) {
	cred, err := config.GetDeploymentOAuthCredentials(deployment, provider)
	if err != nil {
		return nil, err
	}

	conf := &oauth2.Config{
		ClientID:     cred.ClientID,
		ClientSecret: cred.ClientSecret,
		Scopes:       cred.Scopes,
	}

	if deployment.Mode == model.DeploymentModeProduction {
		conf.RedirectURL = fmt.Sprintf(
			"https://%s/sso-callback",
			deployment.FrontendHost,
		)
	} else {
		// For staging, use the OAuth relay service (no trailing slash)
		conf.RedirectURL = "https://ssocallback.wacht.services"
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
	case model.SocialConnectionProviderGitLab:
		conf.Endpoint = config.GitLabOAuthEndpoint
	}

	return conf, nil
}

func ExchangeTokenForUser(
	token *oauth2.Token,
	ssoProvider model.SocialConnectionProvider,
) (*OAuthUser, error) {
	switch ssoProvider {
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
		req, err := http.NewRequest(
			"GET",
			"https://graph.facebook.com/me?fields=id,name,email,first_name,last_name",
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
			FirstName: res["first_name"].(string),
			LastName:  res["last_name"].(string),
			Email:     res["email"].(string),
		}, nil
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

		email := ""
		if res["mail"] != nil {
			email = res["mail"].(string)
		} else if res["userPrincipalName"] != nil {
			email = res["userPrincipalName"].(string)
		}

		return &OAuthUser{
			FirstName: res["givenName"].(string),
			LastName:  res["surname"].(string),
			Email:     email,
		}, nil
	case model.SocialConnectionProviderLinkedIn:
		req, err := http.NewRequest(
			"GET",
			"https://api.linkedin.com/v2/userinfo",
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

		// LinkedIn OpenID Connect response format
		firstName := ""
		lastName := ""
		email := ""

		if givenName, ok := res["given_name"].(string); ok {
			firstName = givenName
		}
		if familyName, ok := res["family_name"].(string); ok {
			lastName = familyName
		}
		if emailAddr, ok := res["email"].(string); ok {
			email = emailAddr
		}

		if firstName == "" && lastName == "" {
			if name, ok := res["name"].(string); ok {
				nameParts := strings.Split(name, " ")
				if len(nameParts) > 0 {
					firstName = nameParts[0]
				}
				if len(nameParts) > 1 {
					lastName = strings.Join(nameParts[1:], " ")
				}
			}
		}

		return &OAuthUser{
			FirstName: firstName,
			LastName:  lastName,
			Email:     email,
		}, nil
	case model.SocialConnectionProviderDiscord:
		req, err := http.NewRequest(
			"GET",
			"https://discord.com/api/users/@me",
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

		username := res["username"].(string)
		globalName := ""
		if res["global_name"] != nil {
			globalName = res["global_name"].(string)
		}

		displayName := globalName
		if displayName == "" {
			displayName = username
		}

		nameParts := strings.Split(displayName, " ")
		firstName := nameParts[0]
		lastName := ""
		if len(nameParts) > 1 {
			lastName = strings.Join(nameParts[1:], " ")
		}

		return &OAuthUser{
			FirstName: firstName,
			LastName:  lastName,
			Email:     res["email"].(string),
		}, nil
	case model.SocialConnectionProviderX:
		userReq, err := http.NewRequest(
			"GET",
			"https://api.twitter.com/2/users/me?user.fields=name,username,verified,profile_image_url",
			nil,
		)
		if err != nil {
			return nil, err
		}

		userReq.Header.Set("Authorization", "Bearer "+token.AccessToken)
		userResp, err := http.DefaultClient.Do(userReq)
		if err != nil {
			return nil, err
		}
		defer userResp.Body.Close()

		var userRes map[string]any
		if err := json.NewDecoder(userResp.Body).Decode(&userRes); err != nil {
			return nil, err
		}

		userData, ok := userRes["data"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid X API response format")
		}

		name, _ := userData["name"].(string)
		userID, _ := userData["id"].(string)

		nameParts := strings.Split(name, " ")
		firstName := nameParts[0]
		lastName := ""
		if len(nameParts) > 1 {
			lastName = strings.Join(nameParts[1:], " ")
		}

		emailReq, err := http.NewRequest(
			"GET",
			"https://api.twitter.com/2/users/"+userID+"?user.fields=email",
			nil,
		)
		if err != nil {
			return nil, err
		}

		emailReq.Header.Set("Authorization", "Bearer "+token.AccessToken)
		emailResp, err := http.DefaultClient.Do(emailReq)
		if err != nil {
			return nil, err
		}
		defer emailResp.Body.Close()

		var emailRes map[string]any
		if err := json.NewDecoder(emailResp.Body).Decode(&emailRes); err != nil {
			return nil, err
		}

		email := ""
		if emailData, ok := emailRes["data"].(map[string]any); ok {
			if emailAddr, ok := emailData["email"].(string); ok {
				email = emailAddr
			}
		}

		if email == "" {
			return nil, fmt.Errorf("X email not available - ensure users.email scope is approved and user has verified email")
		}

		return &OAuthUser{
			FirstName: firstName,
			LastName:  lastName,
			Email:     email,
		}, nil
	case model.SocialConnectionProviderGitLab:
		req, err := http.NewRequest(
			"GET",
			"https://gitlab.com/api/v4/user",
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

		name := res["name"].(string)
		nameParts := strings.Split(name, " ")
		firstName := nameParts[0]
		lastName := ""
		if len(nameParts) > 1 {
			lastName = strings.Join(nameParts[1:], " ")
		}

		return &OAuthUser{
			FirstName: firstName,
			LastName:  lastName,
			Email:     res["email"].(string),
		}, nil
	case model.SocialConnectionProviderApple:
		idToken := token.Extra("id_token")
		if idToken == nil {
			return nil, fmt.Errorf("no id_token provided by Apple")
		}

		idTokenStr, ok := idToken.(string)
		if !ok {
			return nil, fmt.Errorf("invalid id_token format from Apple")
		}

		parts := strings.Split(idTokenStr, ".")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid JWT format from Apple")
		}

		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode Apple JWT payload: %v", err)
		}

		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			return nil, fmt.Errorf("failed to parse Apple JWT claims: %v", err)
		}

		email, _ := claims["email"].(string)
		emailVerified, _ := claims["email_verified"].(bool)

		firstName := ""
		lastName := ""

		if name, ok := claims["name"].(map[string]any); ok {
			if givenName, ok := name["firstName"].(string); ok {
				firstName = givenName
			}
			if familyName, ok := name["lastName"].(string); ok {
				lastName = familyName
			}
		}

		if firstName == "" && email != "" {
			emailParts := strings.Split(email, "@")
			if len(emailParts) > 0 {
				firstName = emailParts[0]
			}
		}

		if !emailVerified {
			return nil, fmt.Errorf("Apple email not verified")
		}

		return &OAuthUser{
			FirstName: firstName,
			LastName:  lastName,
			Email:     email,
		}, nil
	}
	return nil, nil
}

func GenerateOAuthConnectURL(
	provider string,
	stateToken string,
	customRedirectURI string,
	deployment *model.Deployment,
) (string, error) {
	var ssoProvider model.SocialConnectionProvider
	switch provider {
	case "google_oauth":
		ssoProvider = model.SocialConnectionProviderGoogle
	case "github_oauth":
		ssoProvider = model.SocialConnectionProviderGitHub
	case "microsoft_oauth":
		ssoProvider = model.SocialConnectionProviderMicrosoft
	case "facebook_oauth":
		ssoProvider = model.SocialConnectionProviderFacebook
	case "x_oauth":
		ssoProvider = model.SocialConnectionProviderX
	case "linkedin_oauth":
		ssoProvider = model.SocialConnectionProviderLinkedIn
	case "gitlab_oauth":
		ssoProvider = model.SocialConnectionProviderGitLab
	case "discord_oauth":
		ssoProvider = model.SocialConnectionProviderDiscord
	case "apple_oauth":
		ssoProvider = model.SocialConnectionProviderApple
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}

	cred, err := config.GetDeploymentOAuthCredentials(deployment, ssoProvider)
	if err != nil {
		return "", err
	}

	conf := &oauth2.Config{
		ClientID:     cred.ClientID,
		ClientSecret: cred.ClientSecret,
		Scopes:       cred.Scopes,
	}

	if deployment.Mode == model.DeploymentModeProduction {
		conf.RedirectURL = fmt.Sprintf(
			"https://%s/sso-callback",
			deployment.FrontendHost,
		)
	} else {
		conf.RedirectURL = "https://ssocallback.wacht.services"
	}

	switch ssoProvider {
	case model.SocialConnectionProviderGoogle:
		conf.Endpoint = google.Endpoint
	case model.SocialConnectionProviderGitHub:
		conf.Endpoint = github.Endpoint
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
	case model.SocialConnectionProviderDiscord:
		conf.Endpoint = config.DiscordOAuthEndpoint
	case model.SocialConnectionProviderGitLab:
		conf.Endpoint = config.GitLabOAuthEndpoint
	case model.SocialConnectionProviderApple:
		conf.Endpoint = config.AppleOAuthEndpoint
	}

	url := conf.AuthCodeURL(stateToken)

	return url, nil
}

func GetVerificationStrategyForProvider(provider string) model.VerificationStrategy {
	switch provider {
	case "google_oauth":
		return model.OauthGoogle
	case "github_oauth":
		return model.OauthGithub
	case "microsoft_oauth":
		return model.OauthMicrosoft
	case "facebook_oauth":
		return model.OauthFacebook
	case "linkedin_oauth":
		return model.OauthLinkedIn
	case "discord_oauth":
		return model.OauthDiscord
	case "apple_oauth":
		return model.OauthApple
	default:
		return model.Otp
	}
}
