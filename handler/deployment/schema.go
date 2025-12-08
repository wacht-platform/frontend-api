package deployment

// ValidateInvitationResponse represents the response for invitation validation
type ValidateInvitationResponse struct {
	Valid     bool   `json:"valid"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Email     string `json:"email,omitempty"`
	Message   string `json:"message,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// AcceptInvitationRequest represents the request to accept an invitation
type AcceptInvitationRequest struct {
	Token string `json:"token" validate:"required"`
	Email string `json:"email" validate:"required,email"`
}

// AcceptInvitationResponse represents the response after accepting an invitation
type AcceptInvitationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
