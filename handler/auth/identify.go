package auth

import (
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/service"
)

type IdentifyRequest struct {
	Identifier string `json:"identifier" form:"identifier"`
}

type IdentifyResponse struct {
	Strategy     string  `json:"strategy"`
	ConnectionID *string `json:"connection_id,omitempty"`
	IdpURL       *string `json:"idp_url,omitempty"`
	Provider     *string `json:"provider,omitempty"`
}

func (h *Handler) Identify(c *fiber.Ctx) error {
	b, validation := handler.Validate[IdentifyRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	if b.Identifier == "" {
		return handler.SendBadRequest(c, nil, "Identifier is required")
	}

	deployment := handler.GetDeployment(c)
	identifier := strings.TrimSpace(strings.ToLower(b.Identifier))

	parts := strings.Split(identifier, "@")
	if len(parts) != 2 {
		return handler.SendSuccess(c, IdentifyResponse{Strategy: "password"})
	}
	domain := parts[1]

	ssoService := service.NewSSOService()
	orgDomain, err := ssoService.GetVerifiedDomain(domain, deployment.ID)
	if err == nil && orgDomain != nil {
		connection, err := ssoService.GetConnectionByDomain(orgDomain.ID)
		if err == nil && connection != nil {
			connectionID := formatUint64(connection.ID)
			return handler.SendSuccess(c, IdentifyResponse{
				Strategy:     "sso",
				ConnectionID: &connectionID,
				IdpURL:       &connection.IdpSSOURL,
			})
		}
	}

	email, err := h.service.FindUserByEmail(identifier, deployment.ID)
	if err != nil {
		return handler.SendSuccess(c, IdentifyResponse{Strategy: "password"})
	}

	if email.User.Password == "" && len(email.User.SocialConnections) > 0 {
		provider := email.User.SocialConnections[0].Provider
		if isSocialProviderConfigured(deployment, provider) {
			providerStr := string(provider)
			return handler.SendSuccess(c, IdentifyResponse{
				Strategy: "social",
				Provider: &providerStr,
			})
		}
	}

	return handler.SendSuccess(c, IdentifyResponse{Strategy: "password"})
}

func isSocialProviderConfigured(deployment model.Deployment, provider model.SocialConnectionProvider) bool {
	for _, conn := range deployment.SocialConnections {
		if conn.Provider == provider && conn.Enabled {
			if deployment.IsProduction() {
				return conn.Credentials != nil &&
					conn.Credentials.ClientID != "" &&
					conn.Credentials.ClientSecret != ""
			}
			return true
		}
	}
	return false
}

func formatUint64(id uint64) string {
	return strconv.FormatUint(id, 10)
}
