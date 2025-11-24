package model

type EligibilityRestrictionType string

const (
	EligibilityRestrictionNone             EligibilityRestrictionType = "none"
	EligibilityRestrictionIPNotAllowed     EligibilityRestrictionType = "ip_not_allowed"
	EligibilityRestrictionMFARequired      EligibilityRestrictionType = "mfa_required"
	EligibilityRestrictionIPAndMFARequired EligibilityRestrictionType = "ip_and_mfa_required"
)

type EligibilityRestriction struct {
	Type    EligibilityRestrictionType `json:"type"`
	Message string                     `json:"message"`
}
