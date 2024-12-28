package utils

import (
	"strconv"

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
}

func GenerateVerificationUrl(ssoProvider model.SSOProvider, attempt model.SignInAttempt) string {
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
	case model.SSOProviderGitHub:
		conf.Endpoint = github.Endpoint
		url = conf.AuthCodeURL(strconv.FormatUint(uint64(attempt.ID), 10))
	case model.SSOProviderGitLab:
	case model.SSOProviderGoogle:
		conf.Endpoint = google.Endpoint
		url = conf.AuthCodeURL(strconv.FormatUint(uint64(attempt.ID), 10))
	case model.SSOProviderFacebook:
	case model.SSOProviderMicrosoft:
		conf.Endpoint = microsoft.AzureADEndpoint("")
		url = conf.AuthCodeURL(strconv.FormatUint(uint64(attempt.ID), 10))
	case model.SSOProviderLinkedIn:
	case model.SSOProviderDiscord:
	}

	return url
}

func ExchangeTokenForUser(token *oauth2.Token, ssoProvider model.SSOProvider) (*model.User, error) {
	switch ssoProvider {
	case model.SSOProviderX:
	case model.SSOProviderGitHub:
	case model.SSOProviderGitLab:
	case model.SSOProviderGoogle:
	case model.SSOProviderFacebook:
	case model.SSOProviderMicrosoft:
	case model.SSOProviderLinkedIn:
	case model.SSOProviderDiscord:
	}
	return nil, nil
}
