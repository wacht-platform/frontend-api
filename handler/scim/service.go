package scim

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
	"gorm.io/gorm"
)

type SCIMService struct {
	db *gorm.DB
}

func NewSCIMService() *SCIMService {
	return &SCIMService{
		db: database.Connection,
	}
}

func (s *SCIMService) GenerateToken(connectionID, deploymentID, organizationID uint64) (string, *model.SCIMToken, error) {
	tokenBytes := make([]byte, 48)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate token: %w", err)
	}

	plainToken := "scim_" + base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenHash := s.hashToken(plainToken)
	tokenPrefix := plainToken[:12] // "scim_" + 7 chars

	s.db.Where("enterprise_connection_id = ?", connectionID).Delete(&model.SCIMToken{})

	token := &model.SCIMToken{
		ID:                     idgen.NextID(),
		EnterpriseConnectionID: connectionID,
		DeploymentID:           deploymentID,
		OrganizationID:         organizationID,
		TokenHash:              tokenHash,
		TokenPrefix:            tokenPrefix,
		Enabled:                true,
	}

	if err := s.db.Create(token).Error; err != nil {
		return "", nil, fmt.Errorf("failed to save token: %w", err)
	}

	return plainToken, token, nil
}

func (s *SCIMService) ValidateToken(connectionID uint64, bearerToken string) (*model.SCIMToken, *model.EnterpriseConnection, error) {
	tokenHash := s.hashToken(bearerToken)

	var token model.SCIMToken
	if err := s.db.Where("enterprise_connection_id = ? AND token_hash = ? AND enabled = true", connectionID, tokenHash).First(&token).Error; err != nil {
		return nil, nil, fmt.Errorf("invalid token")
	}

	s.db.Model(&token).Update("last_used_at", time.Now())

	var connection model.EnterpriseConnection
	if err := s.db.Where("id = ?", connectionID).First(&connection).Error; err != nil {
		return nil, nil, fmt.Errorf("connection not found")
	}

	return &token, &connection, nil
}

func (s *SCIMService) RevokeToken(connectionID uint64) error {
	return s.db.Where("enterprise_connection_id = ?", connectionID).Delete(&model.SCIMToken{}).Error
}

func (s *SCIMService) GetToken(connectionID uint64) (*model.SCIMToken, error) {
	var token model.SCIMToken
	if err := s.db.Where("enterprise_connection_id = ?", connectionID).First(&token).Error; err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *SCIMService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *SCIMService) FindUserByExternalID(connectionID uint64, externalID string) (*model.User, *model.SCIMExternalID, error) {
	var mapping model.SCIMExternalID
	if err := s.db.Where("enterprise_connection_id = ? AND external_id = ?", connectionID, externalID).
		Preload("User").
		First(&mapping).Error; err != nil {
		return nil, nil, err
	}
	return mapping.User, &mapping, nil
}

func (s *SCIMService) FindUserByEmail(email string, deploymentID uint64) (*model.User, error) {
	var emailAddr model.UserEmailAddress
	if err := s.db.Where("email_address = ? AND deployment_id = ?", strings.ToLower(email), deploymentID).
		Preload("User").
		First(&emailAddr).Error; err != nil {
		return nil, err
	}
	if emailAddr.User.ID == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &emailAddr.User, nil
}

func (s *SCIMService) CreateUser(
	tx *gorm.DB,
	scimUser *SCIMUser,
	connection *model.EnterpriseConnection,
	deployment *model.Deployment,
) (*model.User, error) {
	email := strings.ToLower(scimUser.GetPrimaryEmail())
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}

	primaryAddressID := idgen.NextID()
	userID := idgen.NextID()

	firstName := ""
	lastName := ""
	if scimUser.Name != nil {
		firstName = scimUser.Name.GivenName
		lastName = scimUser.Name.FamilyName
	}
	if firstName == "" && scimUser.DisplayName != "" {
		parts := strings.SplitN(scimUser.DisplayName, " ", 2)
		firstName = parts[0]
		if len(parts) > 1 {
			lastName = parts[1]
		}
	}

	user := model.User{
		Model:                 model.Model{ID: userID},
		FirstName:             firstName,
		LastName:              lastName,
		Username:              scimUser.UserName,
		SchemaVersion:         model.SchemaVersionV1,
		SecondFactorPolicy:    deployment.AuthSettings.SecondFactorPolicy,
		DeploymentID:          deployment.ID,
		PrimaryEmailAddressID: &primaryAddressID,
		Disabled:              !scimUser.IsActive(),
	}

	if err := tx.Create(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	emailRecord := model.UserEmailAddress{
		Model:                model.Model{ID: primaryAddressID},
		DeploymentID:         deployment.ID,
		EmailAddress:         email,
		IsPrimary:            true,
		Verified:             true,
		VerifiedAt:           time.Now(),
		VerificationStrategy: model.VerificationStrategySCIM,
		UserID:               &userID,
	}

	if err := tx.Create(&emailRecord).Error; err != nil {
		return nil, fmt.Errorf("failed to create email: %w", err)
	}

	externalID := scimUser.ExternalId
	if externalID == "" {
		externalID = scimUser.ID
	}
	if externalID == "" {
		externalID = email // Fallback to email as external ID
	}

	mapping := model.SCIMExternalID{
		ID:                     idgen.NextID(),
		EnterpriseConnectionID: connection.ID,
		DeploymentID:           deployment.ID,
		ExternalID:             externalID,
		UserID:                 userID,
	}

	if err := tx.Create(&mapping).Error; err != nil {
		return nil, fmt.Errorf("failed to create external ID mapping: %w", err)
	}

	if err := s.addUserToOrganization(tx, userID, connection.OrganizationID, deployment); err != nil {
		return nil, fmt.Errorf("failed to add user to organization: %w", err)
	}

	return &user, nil
}

func (s *SCIMService) UpdateUser(tx *gorm.DB, user *model.User, scimUser *SCIMUser) error {
	updates := make(map[string]interface{})

	if scimUser.Name != nil {
		if scimUser.Name.GivenName != "" {
			updates["first_name"] = scimUser.Name.GivenName
		}
		if scimUser.Name.FamilyName != "" {
			updates["last_name"] = scimUser.Name.FamilyName
		}
	}

	if scimUser.UserName != "" && scimUser.UserName != user.Username {
		updates["username"] = scimUser.UserName
	}

	if scimUser.Active != nil {
		updates["disabled"] = !*scimUser.Active
	}

	if len(updates) > 0 {
		if err := tx.Model(user).Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to update user: %w", err)
		}
	}

	newEmail := strings.ToLower(scimUser.GetPrimaryEmail())
	if newEmail != "" && user.PrimaryEmailAddressID != nil {
		var existingEmail model.UserEmailAddress
		if err := tx.Where("id = ?", *user.PrimaryEmailAddressID).First(&existingEmail).Error; err == nil {
			if existingEmail.EmailAddress != newEmail {
				tx.Model(&existingEmail).Update("email_address", newEmail)
			}
		}
	}

	return nil
}

func (s *SCIMService) DeactivateUser(tx *gorm.DB, userID uint64) error {
	return tx.Model(&model.User{}).Where("id = ?", userID).Update("disabled", true).Error
}

func (s *SCIMService) GetUserByID(userID uint64, deploymentID uint64) (*model.User, error) {
	var user model.User
	if err := s.db.Where("id = ? AND deployment_id = ?", userID, deploymentID).
		Preload("UserEmailAddresses").
		First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *SCIMService) ListUsers(organizationID, deploymentID uint64, startIndex, count int, filter string) ([]model.User, int, error) {
	query := s.db.
		Joins("JOIN organization_memberships ON organization_memberships.user_id = users.id").
		Where("organization_memberships.organization_id = ? AND users.deployment_id = ?", organizationID, deploymentID)

	if filter != "" {
		query = s.applyFilter(query, filter)
	}

	var totalCount int64
	if err := query.Model(&model.User{}).Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	if totalCount == 0 {
		return []model.User{}, 0, nil
	}

	offset := max(startIndex-1, 0)
	if count <= 0 {
		count = 100
	}

	var users []model.User
	if err := query.Offset(offset).Limit(count).
		Preload("UserEmailAddresses").
		Find(&users).Error; err != nil {
		return nil, 0, err
	}

	return users, int(totalCount), nil
}

func (s *SCIMService) FindGroupByExternalID(connectionID uint64, externalID string) (*model.SCIMGroup, error) {
	var group model.SCIMGroup
	if err := s.db.Where("enterprise_connection_id = ? AND external_id = ?", connectionID, externalID).
		Preload("Members").
		Preload("OrganizationRole").
		First(&group).Error; err != nil {
		return nil, err
	}
	return &group, nil
}

func (s *SCIMService) CreateGroup(
	tx *gorm.DB,
	scimGroup *SCIMGroup,
	connection *model.EnterpriseConnection,
	deploymentID uint64,
) (*model.SCIMGroup, error) {
	externalID := scimGroup.ExternalId
	if externalID == "" {
		externalID = scimGroup.ID
	}
	if externalID == "" {
		externalID = scimGroup.DisplayName // Fallback to displayName
	}

	group := model.SCIMGroup{
		ID:                     idgen.NextID(),
		EnterpriseConnectionID: connection.ID,
		DeploymentID:           deploymentID,
		OrganizationID:         connection.OrganizationID,
		ExternalID:             externalID,
		DisplayName:            scimGroup.DisplayName,
	}

	var role model.OrganizationRole
	err := tx.Where("deployment_id = ? AND (organization_id = ? OR organization_id IS NULL) AND LOWER(name) = LOWER(?)",
		deploymentID, connection.OrganizationID, scimGroup.DisplayName).
		First(&role).Error

	if err != nil {
		role = model.OrganizationRole{
			Model:          model.Model{ID: idgen.NextID()},
			OrganizationID: &connection.OrganizationID,
			Name:           scimGroup.DisplayName,
			Permissions:    []string{"organization:member"},
			DeploymentID:   deploymentID,
		}
		if createErr := tx.Create(&role).Error; createErr != nil {
			return nil, fmt.Errorf("failed to create role for group: %w", createErr)
		}
	}
	group.OrganizationRoleID = &role.ID

	if err := tx.Create(&group).Error; err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	if len(scimGroup.Members) > 0 {
		if err := s.updateGroupMembers(tx, &group, scimGroup.Members, connection); err != nil {
			return nil, err
		}
	}

	return &group, nil
}

func (s *SCIMService) UpdateGroupMembers(tx *gorm.DB, group *model.SCIMGroup, members []SCIMMember, connection *model.EnterpriseConnection) error {
	return s.updateGroupMembers(tx, group, members, connection)
}

func (s *SCIMService) updateGroupMembers(tx *gorm.DB, group *model.SCIMGroup, members []SCIMMember, connection *model.EnterpriseConnection) error {
	tx.Where("scim_group_id = ?", group.ID).Delete(&model.SCIMGroupMember{})

	for _, member := range members {
		userID, err := s.resolveUserID(member.Value, connection.ID, connection.DeploymentID)
		if err != nil {
			continue // Skip members we can't resolve
		}

		groupMember := model.SCIMGroupMember{
			SCIMGroupID: group.ID,
			UserID:      userID,
		}

		if err := tx.Create(&groupMember).Error; err != nil {
			continue // Skip on duplicate
		}

		if group.OrganizationRoleID != nil {
			s.assignRoleToUser(tx, userID, group.OrganizationID, *group.OrganizationRoleID)
		}
	}

	return nil
}

func (s *SCIMService) DeleteGroup(tx *gorm.DB, groupID uint64) error {
	var group model.SCIMGroup
	if err := tx.Preload("Members").Where("id = ?", groupID).First(&group).Error; err != nil {
		return err
	}

	if group.OrganizationRoleID != nil {
		for _, member := range group.Members {
			s.removeRoleFromUser(tx, member.UserID, group.OrganizationID, *group.OrganizationRoleID)
		}
	}

	return tx.Delete(&model.SCIMGroup{}, groupID).Error
}

func (s *SCIMService) ListGroups(connectionID uint64, startIndex, count int) ([]model.SCIMGroup, int, error) {
	var totalCount int64
	if err := s.db.Model(&model.SCIMGroup{}).
		Where("enterprise_connection_id = ?", connectionID).
		Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	offset := startIndex - 1
	if offset < 0 {
		offset = 0
	}
	if count <= 0 {
		count = 100
	}

	var groups []model.SCIMGroup
	if err := s.db.Where("enterprise_connection_id = ?", connectionID).
		Offset(offset).Limit(count).
		Preload("Members").
		Find(&groups).Error; err != nil {
		return nil, 0, err
	}

	return groups, int(totalCount), nil
}

func (s *SCIMService) GetGroupByID(groupID, connectionID uint64) (*model.SCIMGroup, error) {
	var group model.SCIMGroup
	if err := s.db.Where("id = ? AND enterprise_connection_id = ?", groupID, connectionID).
		Preload("Members").
		First(&group).Error; err != nil {
		return nil, err
	}
	return &group, nil
}

func (s *SCIMService) addUserToOrganization(tx *gorm.DB, userID, organizationID uint64, deployment *model.Deployment) error {
	var count int64
	tx.Model(&model.OrganizationMembership{}).
		Where("organization_id = ? AND user_id = ?", organizationID, userID).
		Count(&count)

	if count > 0 {
		return nil
	}

	membershipID := idgen.NextID()
	membership := model.OrganizationMembership{
		Model:          model.Model{ID: membershipID},
		OrganizationID: organizationID,
		UserID:         userID,
	}

	if err := tx.Create(&membership).Error; err != nil {
		return err
	}

	if deployment != nil && deployment.B2BSettings.DefaultOrgMemberRoleID != 0 {
		roleAssoc := model.OrgMembershipRoleAssoc{
			OrganizationMembershipID: membershipID,
			OrganizationRoleID:       deployment.B2BSettings.DefaultOrgMemberRoleID,
		}
		tx.Create(&roleAssoc)
	}

	return nil
}

func (s *SCIMService) resolveUserID(scimID string, connectionID, deploymentID uint64) (uint64, error) {
	if userID, err := strconv.ParseUint(scimID, 10, 64); err == nil {
		var user model.User
		if err := s.db.Where("id = ? AND deployment_id = ?", userID, deploymentID).First(&user).Error; err == nil {
			return userID, nil
		}
	}

	// Try to find via external ID mapping
	var mapping model.SCIMExternalID
	if err := s.db.Where("enterprise_connection_id = ? AND external_id = ?", connectionID, scimID).
		First(&mapping).Error; err == nil {
		return mapping.UserID, nil
	}

	return 0, fmt.Errorf("user not found: %s", scimID)
}

func (s *SCIMService) assignRoleToUser(tx *gorm.DB, userID, organizationID, roleID uint64) {
	// Find membership
	var membership model.OrganizationMembership
	if err := tx.Where("organization_id = ? AND user_id = ?", organizationID, userID).
		First(&membership).Error; err != nil {
		return
	}

	// Check if role already assigned
	var count int64
	tx.Table("organization_membership_roles").
		Where("organization_membership_id = ? AND organization_role_id = ?", membership.ID, roleID).
		Count(&count)

	if count > 0 {
		return
	}

	// Assign role
	tx.Exec(
		"INSERT INTO organization_membership_roles (organization_membership_id, organization_role_id, organization_id) VALUES (?, ?, ?)",
		membership.ID, roleID, organizationID,
	)
}

func (s *SCIMService) removeRoleFromUser(tx *gorm.DB, userID, organizationID, roleID uint64) {
	var membership model.OrganizationMembership
	if err := tx.Where("organization_id = ? AND user_id = ?", organizationID, userID).
		First(&membership).Error; err != nil {
		return
	}

	tx.Exec(
		"DELETE FROM organization_membership_roles WHERE organization_membership_id = ? AND organization_role_id = ?",
		membership.ID, roleID,
	)
}

func (s *SCIMService) applyFilter(query *gorm.DB, filter string) *gorm.DB {
	filter = strings.TrimSpace(filter)

	if strings.HasPrefix(strings.ToLower(filter), "username eq ") {
		value := s.extractFilterValue(filter[12:])
		if value != "" {
			return query.Where("username = ?", value)
		}
	}

	if strings.HasPrefix(strings.ToLower(filter), "emails.value eq ") {
		value := s.extractFilterValue(filter[16:])
		if value != "" {
			var userIDs []uint64
			s.db.Model(&model.UserEmailAddress{}).
				Where("LOWER(email_address) = LOWER(?)", value).
				Pluck("user_id", &userIDs)
			if len(userIDs) > 0 {
				return query.Where("id IN ?", userIDs)
			}
			return query.Where("1 = 0") // No match
		}
	}

	if strings.HasPrefix(strings.ToLower(filter), "externalid eq ") {
		value := s.extractFilterValue(filter[14:])
		if value != "" {
			var userIDs []uint64
			s.db.Model(&model.SCIMExternalID{}).
				Where("external_id = ?", value).
				Pluck("user_id", &userIDs)
			if len(userIDs) > 0 {
				return query.Where("id IN ?", userIDs)
			}
			return query.Where("1 = 0") // No match
		}
	}

	return query
}

func (s *SCIMService) extractFilterValue(s2 string) string {
	s2 = strings.TrimSpace(s2)
	if strings.HasPrefix(s2, "\"") && strings.HasSuffix(s2, "\"") {
		return s2[1 : len(s2)-1]
	}
	return s2
}

func (s *SCIMService) ConvertUserToSCIM(user *model.User, baseURL string, connectionID uint64) *SCIMUser {
	return s.convertUserToSCIMWithExternalID(user, baseURL, connectionID, "")
}

func (s *SCIMService) ConvertUsersToSCIM(users []model.User, baseURL string, connectionID uint64) []*SCIMUser {
	if len(users) == 0 {
		return []*SCIMUser{}
	}

	userIDs := make([]uint64, len(users))
	for i, u := range users {
		userIDs[i] = u.ID
	}

	var mappings []model.SCIMExternalID
	s.db.Where("user_id IN ? AND enterprise_connection_id = ?", userIDs, connectionID).Find(&mappings)

	externalIDMap := make(map[uint64]string)
	for _, m := range mappings {
		externalIDMap[m.UserID] = m.ExternalID
	}

	result := make([]*SCIMUser, len(users))
	for i, user := range users {
		result[i] = s.convertUserToSCIMWithExternalID(&user, baseURL, connectionID, externalIDMap[user.ID])
	}
	return result
}

func (s *SCIMService) convertUserToSCIMWithExternalID(user *model.User, baseURL string, connectionID uint64, externalID string) *SCIMUser {
	if externalID == "" {
		var mapping model.SCIMExternalID
		if err := s.db.Where("user_id = ? AND enterprise_connection_id = ?", user.ID, connectionID).
			First(&mapping).Error; err == nil {
			externalID = mapping.ExternalID
		}
	}

	scimUser := &SCIMUser{
		Schemas:    []string{SchemaUser},
		ID:         fmt.Sprintf("%d", user.ID),
		ExternalId: externalID,
		UserName:   user.Username,
		Name: &SCIMName{
			GivenName:  user.FirstName,
			FamilyName: user.LastName,
			Formatted:  strings.TrimSpace(user.FirstName + " " + user.LastName),
		},
		DisplayName: strings.TrimSpace(user.FirstName + " " + user.LastName),
		Active:      boolPtr(!user.Disabled),
		Meta: &SCIMMeta{
			ResourceType: "User",
			Created:      user.CreatedAt.Format(time.RFC3339),
			LastModified: user.UpdatedAt.Format(time.RFC3339),
			Location:     fmt.Sprintf("%s/scim/v2/%d/Users/%d", baseURL, connectionID, user.ID),
		},
	}

	if len(user.UserEmailAddresses) > 0 {
		for _, email := range user.UserEmailAddresses {
			scimUser.Emails = append(scimUser.Emails, SCIMEmail{
				Value:   email.EmailAddress,
				Type:    "work",
				Primary: email.IsPrimary,
			})
		}
	}

	return scimUser
}

// ConvertGroupToSCIM converts a Wacht SCIM group to SCIM format
func (s *SCIMService) ConvertGroupToSCIM(group *model.SCIMGroup, baseURL string) *SCIMGroup {
	scimGroup := &SCIMGroup{
		Schemas:     []string{SchemaGroup},
		ID:          fmt.Sprintf("%d", group.ID),
		ExternalId:  group.ExternalID,
		DisplayName: group.DisplayName,
		Meta: &SCIMMeta{
			ResourceType: "Group",
			Created:      group.CreatedAt.Format(time.RFC3339),
			LastModified: group.UpdatedAt.Format(time.RFC3339),
			Location:     fmt.Sprintf("%s/scim/v2/%d/Groups/%d", baseURL, group.EnterpriseConnectionID, group.ID),
		},
	}

	// Add members
	for _, member := range group.Members {
		scimGroup.Members = append(scimGroup.Members, SCIMMember{
			Value:   fmt.Sprintf("%d", member.UserID),
			Ref:     fmt.Sprintf("%s/scim/v2/%d/Users/%d", baseURL, group.EnterpriseConnectionID, member.UserID),
			Display: "", // Could be populated with user display name if needed
		})
	}

	return scimGroup
}

func boolPtr(b bool) *bool {
	return &b
}
