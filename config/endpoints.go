package config

import "golang.org/x/oauth2"

var AppleOAuthEndpoint = oauth2.Endpoint{
	AuthURL:  "https://appleid.apple.com/auth/authorize",
	TokenURL: "https://appleid.apple.com/auth/token",
}

var DiscordOAuthEndpoint = oauth2.Endpoint{
	AuthURL:  "https://discord.com/api/oauth2/authorize",
	TokenURL: "https://discord.com/api/oauth2/token",
}

var XOAuthEndpoint = oauth2.Endpoint{
	AuthURL:  "https://x.com/i/oauth2/authorize",
	TokenURL: "https://api.x.com/2/oauth2/token",
}
