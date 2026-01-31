package database

import (
	"fmt"
	"log"

	"github.com/ilabs/wacht-fe/model"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func SyncUserWrapper(db *gorm.DB, userID uint64, context string) {
	go func() {
		if err := SyncUser(db, userID); err != nil {
			log.Printf("[SyncUser] Failed to sync user %d (context: %s): %v", userID, context, err)
		}
	}()
}

func SyncUser(db *gorm.DB, userID uint64) error {
	var user struct {
		ID                uint64
		DeploymentID      uint64
		FirstName         string
		LastName          string
		Username          string
		ProfilePictureURL string
		PrimaryEmail      string
	}

	err := db.Raw(`
		SELECT 
			u.id, u.deployment_id, u.first_name, u.last_name, u.username, u.profile_picture_url,
			COALESCE(pe.email_address, '') as primary_email
		FROM users u
		LEFT JOIN user_email_addresses pe ON u.primary_email_address_id = pe.id
		WHERE u.id = ?
	`, userID).Scan(&user).Error
	if err != nil {
		return fmt.Errorf("failed to fetch user data: %w", err)
	}

	var contacts struct {
		Emails []byte `json:"emails"`
		Phones []byte `json:"phones"`
	}

	err = db.Raw(`
		SELECT
			COALESCE((SELECT json_agg(email_address) FROM user_email_addresses WHERE user_id = ?), '[]'::json) as emails,
			COALESCE((SELECT json_agg(phone_number) FROM user_phone_numbers WHERE user_id = ?), '[]'::json) as phones
	`, userID, userID).Scan(&contacts).Error
	if err != nil {
		return fmt.Errorf("failed to fetch contacts: %w", err)
	}

	var orgData struct {
		IDs   []byte `json:"ids"`
		Roles []byte `json:"roles"`
	}

	err = db.Raw(`
		WITH user_orgs AS (
			SELECT id, organization_id 
			FROM organization_memberships 
			WHERE user_id = ? AND deleted_at IS NULL
		)
		SELECT 
			COALESCE((SELECT json_agg(organization_id) FROM user_orgs), '[]'::json) as ids,
			COALESCE(
				(SELECT json_agg(DISTINCT omr.organization_role_id) 
				 FROM organization_membership_roles omr 
				 JOIN user_orgs uo ON omr.organization_membership_id = uo.id), 
				'[]'::json
			) as roles
	`, userID).Scan(&orgData).Error
	if err != nil {
		return fmt.Errorf("failed to fetch org data: %w", err)
	}

	var wsData struct {
		IDs   []byte `json:"ids"`
		Roles []byte `json:"roles"`
	}
	err = db.Raw(`
		WITH user_workspaces AS (
			SELECT id, workspace_id 
			FROM workspace_memberships 
			WHERE user_id = ? AND deleted_at IS NULL
		)
		SELECT 
			COALESCE((SELECT json_agg(workspace_id) FROM user_workspaces), '[]'::json) as ids,
			COALESCE(
				(SELECT json_agg(DISTINCT wmr.workspace_role_id) 
				 FROM workspace_membership_roles wmr 
				 JOIN user_workspaces uw ON wmr.workspace_membership_id = uw.id), 
				'[]'::json
			) as roles
	`, userID).Scan(&wsData).Error
	if err != nil {
		return fmt.Errorf("failed to fetch workspace data: %w", err)
	}

	asJSON := func(b []byte) datatypes.JSON {
		if len(b) == 0 || string(b) == "null" {
			return datatypes.JSON("[]")
		}
		return datatypes.JSON(b)
	}

	searchUser := model.SearchUser{
		UserID:            user.ID,
		DeploymentID:      user.DeploymentID,
		FirstName:         user.FirstName,
		LastName:          user.LastName,
		Username:          user.Username,
		PrimaryEmail:      user.PrimaryEmail,
		AllEmails:         asJSON(contacts.Emails),
		AllPhoneNumbers:   asJSON(contacts.Phones),
		OrganizationIDs:   asJSON(orgData.IDs),
		WorkspaceIDs:      asJSON(wsData.IDs),
		OrganizationRoles: asJSON(orgData.Roles),
		WorkspaceRoles:    asJSON(wsData.Roles),
		ProfilePictureURL: user.ProfilePictureURL,
	}

	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		UpdateAll: true,
	}).Create(&searchUser).Error; err != nil {
		return fmt.Errorf("failed to upsert search_user: %w", err)
	}

	err = db.Exec(`
		UPDATE search_users
		SET search_vector = (
			setweight(to_tsvector('english', COALESCE(first_name, '')), 'A') ||
			setweight(to_tsvector('english', COALESCE(last_name, '')), 'A') ||
			setweight(to_tsvector('english', COALESCE(username, '')), 'B') ||
			setweight(to_tsvector('english', COALESCE(primary_email, '')), 'B') ||
			setweight(jsonb_to_tsvector('english', all_emails, '["all"]'), 'C') ||
			setweight(jsonb_to_tsvector('english', all_phone_numbers, '["all"]'), 'C')
		)
		WHERE user_id = ?
	`, userID).Error
	if err != nil {
		return fmt.Errorf("failed to update search_vector: %w", err)
	}

	return nil
}
