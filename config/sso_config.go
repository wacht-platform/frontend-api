package config

import "github.com/ilabs/wacht-fe/model"

var ssoConfig = map[string]model.OauthCredentials{
	"google_oauth": {
		ClientID:     "676309606362-8qka5c2tflkt2cjhlq8sqv0o7gn2ne1p.apps.googleusercontent.com",
		ClientSecret: "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",
		RedirectURI:  "http://localhost:5173/auth/sso/google/callback",
		Scopes:       []string{"openid", "email", "profile"},
	},
	"microsoft_oauth": {
		ClientID:     "da77f65d-9dfd-4d47-aff9-59ce2959a0d8",
		ClientSecret: "DyX8Q~ZKrXGxW53JhOFnN0zmK5.HzLY4XT2o3dhl",
		RedirectURI:  "http://localhost:5173/auth/sso/microsoft/callback",
		Scopes:       []string{"openid", "email", "profile"},
	},
	"github_oauth": {
		ClientID:     "Ov23lifkTu6JeKZwE5V0",
		ClientSecret: "1f7319c43486a764a53ceadd6dabacb8582c2d0b",
		RedirectURI:  "http://localhost:5173/auth/sso/github/callback",
		Scopes:       []string{"user:email", "read:user"},
	},
}

func GetDefaultOAuthCredentials(name string) model.OauthCredentials {
	return ssoConfig[name]
}
