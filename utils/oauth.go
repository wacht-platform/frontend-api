package utils

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/model"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

type OAuthUser struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	ImageUrl  string `json:"image_url"`
}

func GenerateVerificationUrl(
	ssoProvider model.SSOProvider,
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
	case model.SSOProviderX:
		conf.Endpoint = oauth2.Endpoint{
			AuthURL:  "https://x.com/i/oauth2/authorize",
			TokenURL: "https://x.com/i/oauth2/token",
		}
		url = conf.AuthCodeURL(
			strconv.FormatUint(uint64(attempt.ID), 10),
		)
	case model.SSOProviderGitHub:
		conf.Endpoint = github.Endpoint
		url = conf.AuthCodeURL(
			strconv.FormatUint(uint64(attempt.ID), 10),
		)
	case model.SSOProviderGitLab:
	case model.SSOProviderGoogle:
		conf.Endpoint = google.Endpoint
		url = conf.AuthCodeURL(
			strconv.FormatUint(uint64(attempt.ID), 10),
		)
	case model.SSOProviderFacebook:
	case model.SSOProviderMicrosoft:
		conf.Endpoint = microsoft.AzureADEndpoint("")
		url = conf.AuthCodeURL(
			strconv.FormatUint(uint64(attempt.ID), 10),
		)

	case model.SSOProviderLinkedIn:
	case model.SSOProviderDiscord:
	}

	return url
}

func ExchangeTokenForUser(
	token *oauth2.Token,
	ssoProvider model.SSOProvider,
) (*OAuthUser, error) {
	switch ssoProvider {
	case model.SSOProviderX:
	case model.SSOProviderGitHub:
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

		var res map[string]interface{}

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

		var emails []map[string]interface{}

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
	case model.SSOProviderGitLab:
	case model.SSOProviderGoogle:
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

		var res map[string]interface{}

		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return nil, err
		}
		return &OAuthUser{
			FirstName: res["given_name"].(string),
			LastName:  res["family_name"].(string),
			Email:     res["email"].(string),
		}, nil
	case model.SSOProviderFacebook:
	case model.SSOProviderMicrosoft:
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

		var res map[string]interface{}

		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return nil, err
		}

		return &OAuthUser{
			FirstName: res["givenName"].(string),
			LastName:  res["surname"].(string),
			Email:     res["mail"].(string),
		}, nil
	case model.SSOProviderLinkedIn:
	case model.SSOProviderDiscord:
	}
	return nil, nil
}
