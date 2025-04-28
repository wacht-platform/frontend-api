package config

import "github.com/aymerick/raymond"

func RegisterHandlebarsHelpers() {
	raymond.RegisterHelper(
		"image",
		func(url string) raymond.SafeString {
			return raymond.SafeString(
				"<img src='" + raymond.Escape(
					url,
				) + "' alt='logo' />",
			)
		},
	)
}
