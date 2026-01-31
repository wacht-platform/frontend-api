package utils

import (
	"net"
	"slices"
	"strings"

	"github.com/ilabs/wacht-fe/model"
	"github.com/lib/pq"
)

// CheckIPAllowed verifies if the client IP is in the allowlist
func CheckIPAllowed(clientIP string, whitelistedIPs pq.StringArray) bool {
	if len(whitelistedIPs) == 0 {
		return true
	}

	for _, allowedIP := range whitelistedIPs {
		allowedIP = strings.TrimSpace(allowedIP)

		// Check for exact match
		if clientIP == allowedIP {
			return true
		}

		// Check for CIDR match
		if strings.Contains(allowedIP, "/") {
			_, ipNet, err := net.ParseCIDR(allowedIP)
			if err == nil {
				if ip := net.ParseIP(clientIP); ip != nil {
					if ipNet.Contains(ip) {
						return true
					}
				}
			}
		}
	}

	return false
}

// CheckUserHasMFA verifies if user has MFA set up
func CheckUserHasMFA(user *model.User) bool {
	if user == nil {
		return false
	}
	return user.UserAuthenticator != nil || user.BackupCodesGenerated
}

// CheckUserHasAdminPermission checks if user has admin permission in their roles
func CheckUserHasAdminPermission(roles []*model.OrganizationRole, adminPermission string) bool {
	for _, role := range roles {
		if slices.Contains(role.Permissions, adminPermission) {
			return true
		}
	}
	return false
}

// CheckUserHasWorkspaceAdminPermission checks if user has workspace admin permission
func CheckUserHasWorkspaceAdminPermission(roles []*model.WorkspaceRole) bool {
	for _, role := range roles {
		if slices.Contains(role.Permissions, "workspace:admin") {
			return true
		}
	}
	return false
}

// CalculateOrganizationEligibility determines if a user can access an organization
func CalculateOrganizationEligibility(
	user *model.User,
	org *model.PublicOrganizationData,
	roles []*model.OrganizationRole,
	clientIP string,
	deployment *model.Deployment,
) *model.EligibilityRestriction {
	// Only organization:admin users can always access regardless of IP/MFA
	if CheckUserHasAdminPermission(roles, "organization:admin") {
		return &model.EligibilityRestriction{
			Type:    model.EligibilityRestrictionNone,
			Message: "",
		}
	}

	ipRestricted := false
	mfaRestricted := false

	// Check IP allowlist if enabled
	if deployment.B2BSettings.IpAllowlistPerOrgEnabled && org.EnableIPRestriction && len(org.WhitelistedIPs) > 0 {
		if !CheckIPAllowed(clientIP, org.WhitelistedIPs) {
			ipRestricted = true
		}
	}

	// Check MFA requirement if enforced
	if deployment.B2BSettings.EnforceMfaPerOrgEnabled && org.EnforceMFASetup && !CheckUserHasMFA(user) {
		mfaRestricted = true
	}

	// Determine restriction type and message
	if ipRestricted && mfaRestricted {
		return &model.EligibilityRestriction{
			Type:    model.EligibilityRestrictionIPAndMFARequired,
			Message: "You must connect from an allowed IP address and set up Multi-Factor Authentication to access this organization.",
		}
	} else if ipRestricted {
		return &model.EligibilityRestriction{
			Type:    model.EligibilityRestrictionIPNotAllowed,
			Message: "You must connect from an allowed IP address to access this organization.",
		}
	} else if mfaRestricted {
		return &model.EligibilityRestriction{
			Type:    model.EligibilityRestrictionMFARequired,
			Message: "You must set up Multi-Factor Authentication to access this organization.",
		}
	}

	return &model.EligibilityRestriction{
		Type:    model.EligibilityRestrictionNone,
		Message: "",
	}
}

// CalculateWorkspaceEligibility determines if a user can access a workspace
func CalculateWorkspaceEligibility(
	user *model.User,
	workspace *model.PublicWorkspaceData,
	workspaceRoles []*model.WorkspaceRole,
	orgRoles []*model.OrganizationRole,
	clientIP string,
	deployment *model.Deployment,
) *model.EligibilityRestriction {
	// Only workspace:admin or organization:admin users can always access
	if CheckUserHasWorkspaceAdminPermission(workspaceRoles) || CheckUserHasAdminPermission(orgRoles, "organization:admin") {
		return &model.EligibilityRestriction{
			Type:    model.EligibilityRestrictionNone,
			Message: "",
		}
	}

	ipRestricted := false
	mfaRestricted := false

	// Check IP allowlist if enabled
	if deployment.B2BSettings.IpAllowlistPerWorkspaceEnabled && workspace.EnableIPRestriction &&
		len(workspace.WhitelistedIPs) > 0 {
		if !CheckIPAllowed(clientIP, workspace.WhitelistedIPs) {
			ipRestricted = true
		}
	}

	// Check MFA requirement if enforced
	if deployment.B2BSettings.EnforceMfaPerWorkspaceEnabled && workspace.EnforceMFASetup && !CheckUserHasMFA(user) {
		mfaRestricted = true
	}

	// Determine restriction type and message
	if ipRestricted && mfaRestricted {
		return &model.EligibilityRestriction{
			Type:    model.EligibilityRestrictionIPAndMFARequired,
			Message: "You must connect from an allowed IP address and set up Multi-Factor Authentication to access this workspace.",
		}
	} else if ipRestricted {
		return &model.EligibilityRestriction{
			Type:    model.EligibilityRestrictionIPNotAllowed,
			Message: "You must connect from an allowed IP address to access this workspace.",
		}
	} else if mfaRestricted {
		return &model.EligibilityRestriction{
			Type:    model.EligibilityRestrictionMFARequired,
			Message: "You must set up Multi-Factor Authentication to access this workspace.",
		}
	}

	return &model.EligibilityRestriction{
		Type:    model.EligibilityRestrictionNone,
		Message: "",
	}
}
