package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/datatypes"
	"gorm.io/plugin/dbresolver"
)

func GetSessionByID(sessionID uint64) (*model.Session, error) {
	session := new(model.Session)

	mainQuery := `
	WITH session_data AS (
		SELECT
			s.id,
			s.created_at,
			s.updated_at,
			s.active_signin_id,

			-- Signin Attempts (JSON aggregated)
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', sia.id,
						'created_at', sia.created_at,
						'updated_at', sia.updated_at,
						'user_id', sia.user_id,
						'identifier_id', sia.identifier_id,
						'session_id', sia.session_id,
						'method', sia.method,
						'sso_provider', sia.sso_provider,
						'expires_at', sia.expires_at,
						'current_step', sia.current_step,
						'remaining_steps', sia.remaining_steps,
						'completed', sia.completed,
						'errored', sia.errored,
						'errors', sia.errors,
						'requires_completion', sia.requires_completion,
						'missing_fields', sia.missing_fields,
						'required_fields', sia.required_fields,
						'first_method_authenticated', sia.first_method_authenticated,
						'second_method_authenticated', sia.second_method_authenticated,
						'second_method_authentication_required', sia.second_method_authentication_required,
						'available_2fa_methods', sia.available_2fa_methods
					) ORDER BY sia.created_at DESC
				) FROM sign_in_attempts sia WHERE sia.session_id = s.id),
				'[]'::json
			) as signin_attempts,

			-- Signup Attempts (JSON aggregated)
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', sua.id,
						'created_at', sua.created_at,
						'updated_at', sua.updated_at,
						'session_id', sua.session_id,
						'first_name', sua.first_name,
						'last_name', sua.last_name,
						'email', sua.email,
						'username', sua.username,
						'phone_number', sua.phone_number,
						'required_fields', sua.required_fields,
						'missing_fields', sua.missing_fields,
						'current_step', sua.current_step,
						'remaining_steps', sua.remaining_steps,
						'sso_provider', sua.sso_provider,
						'is_oauth_signup', sua.is_oauth_signup
					) ORDER BY sua.created_at DESC
				) FROM signup_attempts sua WHERE sua.session_id = s.id),
				'[]'::json
			) as signup_attempts,

			-- All Signins for Session with enhanced data (JSON aggregated)
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', si.id,
						'created_at', si.created_at,
						'updated_at', si.updated_at,
						'session_id', si.session_id,
						'user_id', si.user_id,
						'active_organization_membership_id', si.active_organization_membership_id,
						'active_workspace_membership_id', si.active_workspace_membership_id,
						'expires_at', si.expires_at,
						'last_active_at', si.last_active_at,
						'ip_address', si.ip_address,
						'browser', si.browser,
						'device', si.device,
						'city', si.city,
						'region', si.region,
						'region_code', si.region_code,
						'country', si.country,
						'country_code', si.country_code,
						'user', json_build_object(
							'id', u.id,
							'created_at', u.created_at,
							'updated_at', u.updated_at,
							'first_name', u.first_name,
							'last_name', u.last_name,
							'username', u.username,
							'has_profile_picture', u.has_profile_picture,
							'profile_picture_url', u.profile_picture_url,
							'availability', u.availability,
							'last_password_reset_at', u.last_password_reset_at,
							'schema_version', u.schema_version,
							'disabled', u.disabled,
							'primary_email_address_id', u.primary_email_address_id,
							'primary_phone_number_id', u.primary_phone_number_id,
							'second_factor_policy', u.second_factor_policy,
							'active_organization_membership_id', u.active_organization_membership_id,
							'active_workspace_membership_id', u.active_workspace_membership_id,
							'public_metadata', u.public_metadata,
							'backup_codes_generated', u.backup_codes_generated,
							'primary_email_address', CASE
								WHEN u.primary_email_address_id IS NOT NULL
								THEN (SELECT json_build_object(
									'id', pe.id,
									'email_address', pe.email_address,
									'is_primary', pe.is_primary,
									'verified', pe.verified,
									'verified_at', pe.verified_at,
									'verification_strategy', pe.verification_strategy
								) FROM user_email_addresses pe WHERE pe.id = u.primary_email_address_id)
								ELSE NULL
							END,
							'email_addresses', COALESCE(
								(SELECT json_agg(
									json_build_object(
										'id', ue.id,
										'email_address', ue.email_address,
										'is_primary', ue.is_primary,
										'verified', ue.verified,
										'verified_at', ue.verified_at,
										'verification_strategy', ue.verification_strategy,
										'created_at', ue.created_at,
										'updated_at', ue.updated_at
									) ORDER BY ue.is_primary DESC, ue.created_at
								) FROM user_email_addresses ue WHERE ue.user_id = u.id),
								'[]'::json
							),
							'phone_numbers', COALESCE(
								(SELECT json_agg(
									json_build_object(
										'id', up.id,
										'phone_number', up.phone_number,
										'verified', up.verified,
										'verified_at', up.verified_at,
										'created_at', up.created_at,
										'updated_at', up.updated_at
									) ORDER BY up.created_at
								) FROM user_phone_numbers up WHERE up.user_id = u.id),
								'[]'::json
							),
							'social_connections', COALESCE(
								(SELECT json_agg(
									json_build_object(
										'id', sc.id,
										'provider', sc.provider,
										'user_email_address_id', sc.user_email_address_id,
										'email_address', sc.email_address,
										'first_name', sc.first_name,
										'last_name', sc.last_name,
										'created_at', sc.created_at,
										'updated_at', sc.updated_at
									) ORDER BY sc.created_at
								) FROM social_connections sc WHERE sc.user_id = u.id),
								'[]'::json
							)
						),
						'active_organization_membership', CASE
							WHEN si.active_organization_membership_id IS NOT NULL
							THEN (SELECT json_build_object(
								'id', om.id,
								'organization_id', om.organization_id,
								'user_id', om.user_id,
								'roles', COALESCE(
									(SELECT json_agg(
										json_build_object(
											'id', or_role.id,
											'created_at', or_role.created_at,
											'updated_at', or_role.updated_at,
											'organization_id', or_role.organization_id,
											'name', or_role.name,
											'permissions', or_role.permissions,
											'deployment_id', or_role.deployment_id
										) ORDER BY or_role.name
									) FROM organization_membership_roles omr
									JOIN organization_roles or_role ON omr.organization_role_id = or_role.id
									WHERE omr.organization_membership_id = om.id),
									'[]'::json
								)
							) FROM organization_memberships om WHERE om.id = si.active_organization_membership_id)
							ELSE NULL
						END,
						'active_workspace_membership', CASE
							WHEN si.active_workspace_membership_id IS NOT NULL
							THEN (SELECT json_build_object(
								'id', wm.id,
								'workspace_id', wm.workspace_id,
								'user_id', wm.user_id,
								'organization_membership_id', wm.organization_membership_id,
								'roles', COALESCE(
									(SELECT json_agg(
										json_build_object(
											'id', ws_role.id,
											'created_at', ws_role.created_at,
											'updated_at', ws_role.updated_at,
											'organization_id', ws_role.organization_id,
											'name', ws_role.name,
											'permissions', ws_role.permissions,
											'deployment_id', ws_role.deployment_id,
											'workspace_id', ws_role.workspace_id
										) ORDER BY ws_role.name
									) FROM workspace_membership_roles wmr
									JOIN workspace_roles ws_role ON wmr.workspace_role_id = ws_role.id
									WHERE wmr.workspace_membership_id = wm.id),
									'[]'::json
								)
							) FROM workspace_memberships wm WHERE wm.id = si.active_workspace_membership_id)
							ELSE NULL
						END
					) ORDER BY si.created_at DESC
				) FROM signins si
				LEFT JOIN users u ON si.user_id = u.id
				WHERE si.session_id = s.id),
				'[]'::json
			) as signins

		FROM sessions s
		WHERE s.id = ? AND s.deleted_at IS NULL
	)
	SELECT * FROM session_data`

	var rawResult map[string]interface{}
	err := database.Connection.Clauses(dbresolver.Read).Raw(mainQuery, sessionID).Scan(&rawResult).Error
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	if id, ok := rawResult["id"].(int64); ok {
		session.ID = uint64(id)
	}
	if activeSigninID, ok := rawResult["active_signin_id"].(int64); ok {
		session.ActiveSigninID = &[]uint64{uint64(activeSigninID)}[0]
	}

	// Parse signins JSON
	if signinsData, ok := rawResult["signins"]; ok {
		if signinsJSON, ok := signinsData.(string); ok && signinsJSON != "" && signinsJSON != "[]" {
			var signinsData []map[string]interface{}
			if err := json.Unmarshal([]byte(signinsJSON), &signinsData); err == nil {
				for _, signinData := range signinsData {
					signin := model.Signin{}

					// Parse basic signin fields
					if id, ok := signinData["id"].(float64); ok {
						signin.ID = uint64(id)
					}
					if createdAt, ok := signinData["created_at"].(string); ok {
						if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
							signin.CreatedAt = t
						}
					}
					if updatedAt, ok := signinData["updated_at"].(string); ok {
						if t, err := time.Parse(time.RFC3339, updatedAt); err == nil {
							signin.UpdatedAt = t
						}
					}
					if sessionID, ok := signinData["session_id"].(float64); ok {
						signin.SessionID = uint64(sessionID)
					}
					if userID, ok := signinData["user_id"].(float64); ok {
						signin.UserID = &[]uint64{uint64(userID)}[0]
					}
					if activeOrgMembershipID, ok := signinData["active_organization_membership_id"].(float64); ok {
						signin.ActiveOrganizationMembershipID = &[]uint64{uint64(activeOrgMembershipID)}[0]
					}
					if activeWsMembershipID, ok := signinData["active_workspace_membership_id"].(float64); ok {
						signin.ActiveWorkspaceMembershipID = &[]uint64{uint64(activeWsMembershipID)}[0]
					}
					if expiresAt, ok := signinData["expires_at"].(string); ok {
						signin.ExpiresAt = expiresAt
					}
					if lastActiveAt, ok := signinData["last_active_at"].(string); ok {
						signin.LastActiveAt = lastActiveAt
					}
					if ipAddress, ok := signinData["ip_address"].(string); ok {
						signin.IpAddress = ipAddress
					}
					if browser, ok := signinData["browser"].(string); ok {
						signin.Browser = browser
					}
					if device, ok := signinData["device"].(string); ok {
						signin.Device = device
					}
					if city, ok := signinData["city"].(string); ok {
						signin.City = city
					}
					if region, ok := signinData["region"].(string); ok {
						signin.Region = region
					}
					if regionCode, ok := signinData["region_code"].(string); ok {
						signin.RegionCode = regionCode
					}
					if country, ok := signinData["country"].(string); ok {
						signin.Country = country
					}
					if countryCode, ok := signinData["country_code"].(string); ok {
						signin.CountryCode = countryCode
					}

					// Parse user data
					if userData, ok := signinData["user"].(map[string]interface{}); ok {
						user := &model.User{}
						if id, ok := userData["id"].(float64); ok {
							user.ID = uint64(id)
						}
						if createdAt, ok := userData["created_at"].(string); ok {
							if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
								user.CreatedAt = t
							}
						}
						if updatedAt, ok := userData["updated_at"].(string); ok {
							if t, err := time.Parse(time.RFC3339, updatedAt); err == nil {
								user.UpdatedAt = t
							}
						}
						if firstName, ok := userData["first_name"].(string); ok {
							user.FirstName = firstName
						}
						if lastName, ok := userData["last_name"].(string); ok {
							user.LastName = lastName
						}
						if username, ok := userData["username"].(string); ok {
							user.Username = username
						}
						if disabled, ok := userData["disabled"].(bool); ok {
							user.Disabled = disabled
						}
						if hasProfilePicture, ok := userData["has_profile_picture"].(bool); ok {
							user.HasProfilePicture = hasProfilePicture
						}
						if profilePictureURL, ok := userData["profile_picture_url"].(string); ok {
							user.ProfilePictureURL = profilePictureURL
						}
						if availability, ok := userData["availability"].(string); ok {
							user.Availability = model.UserAvailability(availability)
						}
						if schemaVersion, ok := userData["schema_version"].(string); ok {
							user.SchemaVersion = model.SchemaVersion(schemaVersion)
						}
						if primaryEmailAddressID, ok := userData["primary_email_address_id"].(float64); ok {
							user.PrimaryEmailAddressID = &[]uint64{uint64(primaryEmailAddressID)}[0]
						}
						if primaryPhoneNumberID, ok := userData["primary_phone_number_id"].(float64); ok {
							user.PrimaryPhoneNumberID = &[]uint64{uint64(primaryPhoneNumberID)}[0]
						}
						if secondFactorPolicy, ok := userData["second_factor_policy"].(string); ok {
							user.SecondFactorPolicy = model.SecondFactorPolicy(secondFactorPolicy)
						}
						if backupCodesGenerated, ok := userData["backup_codes_generated"].(bool); ok {
							user.BackupCodesGenerated = backupCodesGenerated
						}
						if publicMetadata, ok := userData["public_metadata"]; ok && publicMetadata != nil {
							// Handle public metadata - it could be a string or already parsed
							switch v := publicMetadata.(type) {
							case string:
								if v != "" && v != "null" {
									var metadata datatypes.JSONMap
									if err := json.Unmarshal([]byte(v), &metadata); err == nil {
										user.PublicMetadata = metadata
									}
								}
							case map[string]interface{}:
								user.PublicMetadata = datatypes.JSONMap(v)
							}
						}

						// Parse primary email address
						if primaryEmailData, ok := userData["primary_email_address"].(map[string]interface{}); ok {
							primaryEmail := &model.UserEmailAddress{}
							if id, ok := primaryEmailData["id"].(float64); ok {
								primaryEmail.ID = uint64(id)
							}
							if emailAddress, ok := primaryEmailData["email_address"].(string); ok {
								primaryEmail.EmailAddress = emailAddress
							}
							if isPrimary, ok := primaryEmailData["is_primary"].(bool); ok {
								primaryEmail.IsPrimary = isPrimary
							}
							if verified, ok := primaryEmailData["verified"].(bool); ok {
								primaryEmail.Verified = verified
							}
							if verificationStrategy, ok := primaryEmailData["verification_strategy"].(string); ok {
								primaryEmail.VerificationStrategy = model.VerificationStrategy(verificationStrategy)
							}
							user.PrimaryEmailAddress = primaryEmail
						}

						// Parse email addresses
						if emailAddressesData, ok := userData["email_addresses"].([]interface{}); ok {
							for _, emailData := range emailAddressesData {
								if emailMap, ok := emailData.(map[string]interface{}); ok {
									email := model.UserEmailAddress{}
									if id, ok := emailMap["id"].(float64); ok {
										email.ID = uint64(id)
									}
									if emailAddress, ok := emailMap["email_address"].(string); ok {
										email.EmailAddress = emailAddress
									}
									if isPrimary, ok := emailMap["is_primary"].(bool); ok {
										email.IsPrimary = isPrimary
									}
									if verified, ok := emailMap["verified"].(bool); ok {
										email.Verified = verified
									}
									if verificationStrategy, ok := emailMap["verification_strategy"].(string); ok {
										email.VerificationStrategy = model.VerificationStrategy(verificationStrategy)
									}
									user.UserEmailAddresses = append(user.UserEmailAddresses, email)
								}
							}
						}

						// Parse phone numbers
						if phoneNumbersData, ok := userData["phone_numbers"].([]interface{}); ok {
							for _, phoneData := range phoneNumbersData {
								if phoneMap, ok := phoneData.(map[string]interface{}); ok {
									phone := model.UserPhoneNumber{}
									if id, ok := phoneMap["id"].(float64); ok {
										phone.ID = uint64(id)
									}
									if phoneNumber, ok := phoneMap["phone_number"].(string); ok {
										phone.PhoneNumber = phoneNumber
									}
									if verified, ok := phoneMap["verified"].(bool); ok {
										phone.Verified = verified
									}
									user.UserPhoneNumbers = append(user.UserPhoneNumbers, phone)
								}
							}
						}

						// Parse social connections
						if socialConnectionsData, ok := userData["social_connections"].([]interface{}); ok {
							for _, socialData := range socialConnectionsData {
								if socialMap, ok := socialData.(map[string]interface{}); ok {
									social := model.SocialConnection{}
									if id, ok := socialMap["id"].(float64); ok {
										social.ID = uint64(id)
									}
									if provider, ok := socialMap["provider"].(string); ok {
										social.Provider = model.SocialConnectionProvider(provider)
									}
									if emailAddress, ok := socialMap["email_address"].(string); ok {
										social.EmailAddress = emailAddress
									}
									if firstName, ok := socialMap["first_name"].(string); ok {
										social.FirstName = firstName
									}
									if lastName, ok := socialMap["last_name"].(string); ok {
										social.LastName = lastName
									}
									user.SocialConnections = append(user.SocialConnections, social)
								}
							}
						}

						signin.User = user
					}

					// Parse active organization membership
					if activeOrgMembershipData, ok := signinData["active_organization_membership"].(map[string]interface{}); ok {
						orgMembership := &model.OrganizationMembership{}
						if id, ok := activeOrgMembershipData["id"].(float64); ok {
							orgMembership.ID = uint64(id)
						}
						if orgID, ok := activeOrgMembershipData["organization_id"].(float64); ok {
							orgMembership.OrganizationID = uint64(orgID)
						}
						if userID, ok := activeOrgMembershipData["user_id"].(float64); ok {
							orgMembership.UserID = uint64(userID)
						}

						// Parse organization roles
						if rolesData, ok := activeOrgMembershipData["roles"].([]interface{}); ok {
							for _, roleData := range rolesData {
								if roleMap, ok := roleData.(map[string]interface{}); ok {
									role := &model.OrganizationRole{}
									if id, ok := roleMap["id"].(float64); ok {
										role.ID = uint64(id)
									}
									if name, ok := roleMap["name"].(string); ok {
										role.Name = name
									}
									if permissions, ok := roleMap["permissions"].([]interface{}); ok {
										for _, perm := range permissions {
											if permStr, ok := perm.(string); ok {
												role.Permissions = append(role.Permissions, permStr)
											}
										}
									}
									orgMembership.Roles = append(orgMembership.Roles, role)
								}
							}
						}

						signin.ActiveOrganizationMembership = orgMembership
					}

					// Parse active workspace membership
					if activeWsMembershipData, ok := signinData["active_workspace_membership"].(map[string]interface{}); ok {
						wsMembership := &model.WorkspaceMembership{}
						if id, ok := activeWsMembershipData["id"].(float64); ok {
							wsMembership.ID = uint64(id)
						}
						if wsID, ok := activeWsMembershipData["workspace_id"].(float64); ok {
							wsMembership.WorkspaceID = uint64(wsID)
						}
						if userID, ok := activeWsMembershipData["user_id"].(float64); ok {
							wsMembership.UserID = uint64(userID)
						}
						if orgMembershipID, ok := activeWsMembershipData["organization_membership_id"].(float64); ok {
							wsMembership.OrganizationMembershipID = uint64(orgMembershipID)
						}

						// Parse workspace roles
						if rolesData, ok := activeWsMembershipData["roles"].([]interface{}); ok {
							for _, roleData := range rolesData {
								if roleMap, ok := roleData.(map[string]interface{}); ok {
									role := &model.WorkspaceRole{}
									if id, ok := roleMap["id"].(float64); ok {
										role.ID = uint64(id)
									}
									if name, ok := roleMap["name"].(string); ok {
										role.Name = name
									}
									if permissions, ok := roleMap["permissions"].([]interface{}); ok {
										for _, perm := range permissions {
											if permStr, ok := perm.(string); ok {
												role.Permissions = append(role.Permissions, permStr)
											}
										}
									}
									wsMembership.Roles = append(wsMembership.Roles, role)
								}
							}
						}

						signin.ActiveWorkspaceMembership = wsMembership
					}

					session.Signins = append(session.Signins, signin)
				}
			} else {
				log.Printf("Failed to unmarshal signins JSON: %v", err)
			}
		}
	}
	
	// Parse signin and signup attempts
	if signinAttemptsData, ok := rawResult["signin_attempts"]; ok {
		if signinAttemptsJSON, ok := signinAttemptsData.(string); ok && signinAttemptsJSON != "" && signinAttemptsJSON != "[]" {
			var attempts []model.SignInAttempt
			if err := json.Unmarshal([]byte(signinAttemptsJSON), &attempts); err == nil {
				session.SigninAttempts = attempts
			}
		}
	}

	if signupAttemptsData, ok := rawResult["signup_attempts"]; ok {
		if signupAttemptsJSON, ok := signupAttemptsData.(string); ok && signupAttemptsJSON != "" && signupAttemptsJSON != "[]" {
			var attempts []model.SignupAttempt
			if err := json.Unmarshal([]byte(signupAttemptsJSON), &attempts); err == nil {
				session.SignupAttempts = attempts
			}
		}
	}
	
	// Find and set the active signin from the list
	if session.ActiveSigninID != nil {
		for i := range session.Signins {
			if session.Signins[i].ID == *session.ActiveSigninID {
				session.ActiveSignin = &session.Signins[i]
				break
			}
		}
	}
	
	return session, nil
}