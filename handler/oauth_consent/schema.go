package oauth_consent

type submitConsentRequest struct {
	Action   string `json:"action" form:"action" validate:"required"`
	Resource string `json:"resource" form:"resource"`
}

type oauthConsentHandoffPayload struct {
	RequestToken     string                        `json:"request_token"`
	Issuer           string                        `json:"issuer"`
	DeploymentID     int64                         `json:"deployment_id"`
	OAuthClientID    int64                         `json:"oauth_client_id"`
	ClientID         string                        `json:"client_id"`
	ClientName       *string                       `json:"client_name"`
	RedirectURI      string                        `json:"redirect_uri"`
	Scopes           []string                      `json:"scopes"`
	ScopeDefinitions []oauthConsentScopeDefinition `json:"scope_definitions"`
	Resource         *string                       `json:"resource"`
	ResourceOptions  []string                      `json:"resource_options"`
	State            *string                       `json:"state"`
	ExpiresAt        int64                         `json:"expires_at"`
}

type oauthConsentScopeDefinition struct {
	Scope                  string  `json:"scope"`
	DisplayName            string  `json:"display_name"`
	Description            string  `json:"description"`
	Archived               bool    `json:"archived"`
	Category               string  `json:"category"`
	OrganizationPermission *string `json:"organization_permission"`
	WorkspacePermission    *string `json:"workspace_permission"`
}

type consentResourceOption struct {
	Value string `json:"value"`
	Type  string `json:"type"`
	ID    string `json:"id"`
	Label string `json:"label"`
}
