package scim

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"gorm.io/gorm"
)

type Handler struct {
	service *SCIMService
}

func NewHandler() *Handler {
	return &Handler{
		service: NewSCIMService(),
	}
}

func (h *Handler) AuthMiddleware(c fiber.Ctx) error {
	connectionIDStr := c.Params("connectionId")
	if connectionIDStr == "" {
		return h.sendSCIMError(c, 400, "Missing connection ID", "invalidValue")
	}

	connectionID, err := strconv.ParseUint(connectionIDStr, 10, 64)
	if err != nil {
		return h.sendSCIMError(c, 400, "Invalid connection ID", "invalidValue")
	}

	// Extract bearer token
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return h.sendSCIMError(c, 401, "Missing Authorization header", "unauthorized")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return h.sendSCIMError(c, 401, "Invalid Authorization header format", "unauthorized")
	}

	bearerToken := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate token
	token, connection, err := h.service.ValidateToken(connectionID, bearerToken)
	if err != nil {
		return h.sendSCIMError(c, 401, "Invalid or expired token", "unauthorized")
	}

	// Use cached deployment from prelude middleware
	deployment := handler.GetDeployment(c)

	// Store in locals for handlers
	c.Locals("scim_token", token)
	c.Locals("scim_connection", connection)
	c.Locals("scim_deployment", &deployment)
	c.Locals("scim_connection_id", connectionID)
	c.Locals("scim_deployment_id", deployment.ID)
	c.Locals("scim_organization_id", connection.OrganizationID)

	return c.Next()
}

func (h *Handler) GetServiceProviderConfig(c fiber.Ctx) error {
	connectionID := c.Locals("scim_connection_id").(uint64)
	baseURL := h.getBaseURL(c)

	config := &ServiceProviderConfig{
		Schemas:          []string{SchemaServiceProviderConfig},
		DocumentationUri: "https://docs.wacht.io/scim",
		Patch: SPConfigSupported{
			Supported: true,
		},
		Bulk: SPConfigBulk{
			Supported:      false,
			MaxOperations:  0,
			MaxPayloadSize: 0,
		},
		Filter: SPConfigFilter{
			Supported:  true,
			MaxResults: 100,
		},
		ChangePassword: SPConfigSupported{
			Supported: false,
		},
		Sort: SPConfigSupported{
			Supported: false,
		},
		Etag: SPConfigSupported{
			Supported: false,
		},
		AuthenticationSchemes: []SPAuthScheme{
			{
				Type:        "oauthbearertoken",
				Name:        "OAuth Bearer Token",
				Description: "Authentication scheme using the OAuth Bearer Token Standard",
				SpecUri:     "https://www.rfc-editor.org/info/rfc6750",
				Primary:     true,
			},
		},
		Meta: &SCIMMeta{
			ResourceType: "ServiceProviderConfig",
			Location:     fmt.Sprintf("%s/scim/v2/%d/ServiceProviderConfig", baseURL, connectionID),
		},
	}

	c.Set("Content-Type", ContentTypeSCIM)
	return c.JSON(config)
}

func (h *Handler) GetSchemas(c fiber.Ctx) error {
	// Simplified schema response - full schema definitions would be quite long
	schemas := []any{
		map[string]any{
			"schemas":     []string{SchemaSchema},
			"id":          SchemaUser,
			"name":        "User",
			"description": "User Account",
		},
		map[string]any{
			"schemas":     []string{SchemaSchema},
			"id":          SchemaGroup,
			"name":        "Group",
			"description": "Group",
		},
	}

	response := NewSCIMListResponse(schemas, len(schemas), 1, len(schemas))
	c.Set("Content-Type", ContentTypeSCIM)
	return c.JSON(response)
}

func (h *Handler) GetResourceTypes(c fiber.Ctx) error {
	connectionID := c.Locals("scim_connection_id").(uint64)
	baseURL := h.getBaseURL(c)

	resourceTypes := []any{
		&ResourceType{
			Schemas:     []string{SchemaResourceType},
			ID:          "User",
			Name:        "User",
			Endpoint:    "/Users",
			Description: "User Account",
			Schema:      SchemaUser,
			Meta: &SCIMMeta{
				ResourceType: "ResourceType",
				Location:     fmt.Sprintf("%s/scim/v2/%d/ResourceTypes/User", baseURL, connectionID),
			},
		},
		&ResourceType{
			Schemas:     []string{SchemaResourceType},
			ID:          "Group",
			Name:        "Group",
			Endpoint:    "/Groups",
			Description: "Group",
			Schema:      SchemaGroup,
			Meta: &SCIMMeta{
				ResourceType: "ResourceType",
				Location:     fmt.Sprintf("%s/scim/v2/%d/ResourceTypes/Group", baseURL, connectionID),
			},
		},
	}

	response := NewSCIMListResponse(resourceTypes, len(resourceTypes), 1, len(resourceTypes))
	c.Set("Content-Type", ContentTypeSCIM)
	return c.JSON(response)
}

func (h *Handler) CreateUser(c fiber.Ctx) error {
	connection := c.Locals("scim_connection").(*model.EnterpriseConnection)
	deployment := c.Locals("scim_deployment").(*model.Deployment)

	var scimUser SCIMUser
	if err := c.Bind().Body(&scimUser); err != nil {
		return h.sendSCIMError(c, 400, "Invalid request body", "invalidSyntax")
	}

	if scimUser.UserName == "" {
		return h.sendSCIMError(c, 400, "userName is required", "invalidValue")
	}

	// Check if user already exists by external ID
	externalID := scimUser.ExternalId
	if externalID == "" {
		externalID = scimUser.ID
	}
	if externalID != "" {
		existingUser, _, err := h.service.FindUserByExternalID(connection.ID, externalID)
		if err == nil && existingUser != nil {
			return h.sendSCIMError(c, 409, "User already exists", "uniqueness")
		}
	}

	// Check by email
	email := scimUser.GetPrimaryEmail()
	if email != "" {
		existingUser, _ := h.service.FindUserByEmail(email, deployment.ID)
		if existingUser != nil {
			return h.sendSCIMError(c, 409, "User with this email already exists", "uniqueness")
		}
	}

	var user *model.User
	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		var err error
		user, err = h.service.CreateUser(tx, &scimUser, connection, deployment)
		return err
	})

	if err != nil {
		return h.sendSCIMError(c, 500, err.Error(), "")
	}

	// Index the SCIM-provisioned user for search (post-commit).
	database.SyncUserWrapper(nil, user.ID, "scim.create")

	// Reload user with associations
	user, _ = h.service.GetUserByID(user.ID, deployment.ID)

	result := h.service.ConvertUserToSCIM(user, h.getBaseURL(c), connection.ID)
	c.Set("Content-Type", ContentTypeSCIM)
	return c.Status(201).JSON(result)
}

func (h *Handler) ListUsers(c fiber.Ctx) error {
	connection := c.Locals("scim_connection").(*model.EnterpriseConnection)
	deploymentID := c.Locals("scim_deployment_id").(uint64)
	organizationID := c.Locals("scim_organization_id").(uint64)

	startIndex, _ := strconv.Atoi(c.Query("startIndex", "1"))
	count, _ := strconv.Atoi(c.Query("count", "100"))
	filter := c.Query("filter", "")

	users, total, err := h.service.ListUsers(organizationID, deploymentID, startIndex, count, filter)
	if err != nil {
		return h.sendSCIMError(c, 500, err.Error(), "")
	}

	scimUsers := h.service.ConvertUsersToSCIM(users, h.getBaseURL(c), connection.ID)
	resources := make([]any, len(scimUsers))
	for i, u := range scimUsers {
		resources[i] = u
	}

	response := NewSCIMListResponse(resources, total, startIndex, len(resources))
	c.Set("Content-Type", ContentTypeSCIM)
	return c.JSON(response)
}

func (h *Handler) GetUser(c fiber.Ctx) error {
	connection := c.Locals("scim_connection").(*model.EnterpriseConnection)
	deploymentID := c.Locals("scim_deployment_id").(uint64)

	userIDStr := c.Params("userId")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		return h.sendSCIMError(c, 400, "Invalid user ID", "invalidValue")
	}

	user, err := h.service.GetUserByID(userID, deploymentID)
	if err != nil {
		return h.sendSCIMError(c, 404, "User not found", "noTarget")
	}

	result := h.service.ConvertUserToSCIM(user, h.getBaseURL(c), connection.ID)
	c.Set("Content-Type", ContentTypeSCIM)
	return c.JSON(result)
}

func (h *Handler) ReplaceUser(c fiber.Ctx) error {
	connection := c.Locals("scim_connection").(*model.EnterpriseConnection)
	deploymentID := c.Locals("scim_deployment_id").(uint64)

	userIDStr := c.Params("userId")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		return h.sendSCIMError(c, 400, "Invalid user ID", "invalidValue")
	}

	var scimUser SCIMUser
	if err := c.Bind().Body(&scimUser); err != nil {
		return h.sendSCIMError(c, 400, "Invalid request body", "invalidSyntax")
	}

	user, err := h.service.GetUserByID(userID, deploymentID)
	if err != nil {
		return h.sendSCIMError(c, 404, "User not found", "noTarget")
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		return h.service.UpdateUser(tx, user, &scimUser)
	})

	if err != nil {
		return h.sendSCIMError(c, 500, err.Error(), "")
	}

	// Re-index the SCIM-updated user for search (post-commit).
	database.SyncUserWrapper(nil, user.ID, "scim.update")

	// Reload user
	user, _ = h.service.GetUserByID(userID, deploymentID)

	result := h.service.ConvertUserToSCIM(user, h.getBaseURL(c), connection.ID)
	c.Set("Content-Type", ContentTypeSCIM)
	return c.JSON(result)
}

func (h *Handler) PatchUser(c fiber.Ctx) error {
	connection := c.Locals("scim_connection").(*model.EnterpriseConnection)
	deploymentID := c.Locals("scim_deployment_id").(uint64)

	userIDStr := c.Params("userId")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		return h.sendSCIMError(c, 400, "Invalid user ID", "invalidValue")
	}

	user, err := h.service.GetUserByID(userID, deploymentID)
	if err != nil {
		return h.sendSCIMError(c, 404, "User not found", "noTarget")
	}

	var patchOp SCIMPatchOp
	if err := c.Bind().Body(&patchOp); err != nil {
		return h.sendSCIMError(c, 400, "Invalid request body", "invalidSyntax")
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		return h.applyUserPatchOperations(tx, user, patchOp.Operations)
	})

	if err != nil {
		return h.sendSCIMError(c, 500, err.Error(), "")
	}

	// Reload user
	user, _ = h.service.GetUserByID(userID, deploymentID)

	result := h.service.ConvertUserToSCIM(user, h.getBaseURL(c), connection.ID)
	c.Set("Content-Type", ContentTypeSCIM)
	return c.JSON(result)
}

func (h *Handler) DeleteUser(c fiber.Ctx) error {
	deploymentID := c.Locals("scim_deployment_id").(uint64)

	userIDStr := c.Params("userId")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		return h.sendSCIMError(c, 400, "Invalid user ID", "invalidValue")
	}

	_, err = h.service.GetUserByID(userID, deploymentID)
	if err != nil {
		return h.sendSCIMError(c, 404, "User not found", "noTarget")
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		return h.service.DeactivateUser(tx, userID)
	})

	if err != nil {
		return h.sendSCIMError(c, 500, err.Error(), "")
	}

	return c.SendStatus(204)
}

func (h *Handler) CreateGroup(c fiber.Ctx) error {
	connection := c.Locals("scim_connection").(*model.EnterpriseConnection)
	deploymentID := c.Locals("scim_deployment_id").(uint64)

	var scimGroup SCIMGroup
	if err := c.Bind().Body(&scimGroup); err != nil {
		return h.sendSCIMError(c, 400, "Invalid request body", "invalidSyntax")
	}

	if scimGroup.DisplayName == "" {
		return h.sendSCIMError(c, 400, "displayName is required", "invalidValue")
	}

	// Check if group already exists
	externalID := scimGroup.ExternalId
	if externalID == "" {
		externalID = scimGroup.ID
	}
	if externalID != "" {
		existingGroup, err := h.service.FindGroupByExternalID(connection.ID, externalID)
		if err == nil && existingGroup != nil {
			return h.sendSCIMError(c, 409, "Group already exists", "uniqueness")
		}
	}

	var group *model.SCIMGroup
	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		var err error
		group, err = h.service.CreateGroup(tx, &scimGroup, connection, deploymentID)
		return err
	})

	if err != nil {
		log.Println(err)
		return h.sendSCIMError(c, 500, err.Error(), "")
	}

	// Reload with members
	group, _ = h.service.GetGroupByID(group.ID, connection.ID)

	result := h.service.ConvertGroupToSCIM(group, h.getBaseURL(c))
	c.Set("Content-Type", ContentTypeSCIM)
	return c.Status(201).JSON(result)
}

func (h *Handler) ListGroups(c fiber.Ctx) error {
	connectionID := c.Locals("scim_connection_id").(uint64)

	startIndex, _ := strconv.Atoi(c.Query("startIndex", "1"))
	count, _ := strconv.Atoi(c.Query("count", "100"))

	groups, total, err := h.service.ListGroups(connectionID, startIndex, count)
	if err != nil {
		return h.sendSCIMError(c, 500, err.Error(), "")
	}

	resources := make([]any, len(groups))
	for i, group := range groups {
		resources[i] = h.service.ConvertGroupToSCIM(&group, h.getBaseURL(c))
	}

	response := NewSCIMListResponse(resources, total, startIndex, len(resources))
	c.Set("Content-Type", ContentTypeSCIM)
	return c.JSON(response)
}

func (h *Handler) GetGroup(c fiber.Ctx) error {
	connectionID := c.Locals("scim_connection_id").(uint64)

	groupIDStr := c.Params("groupId")
	groupID, err := strconv.ParseUint(groupIDStr, 10, 64)
	if err != nil {
		return h.sendSCIMError(c, 400, "Invalid group ID", "invalidValue")
	}

	group, err := h.service.GetGroupByID(groupID, connectionID)
	if err != nil {
		return h.sendSCIMError(c, 404, "Group not found", "noTarget")
	}

	result := h.service.ConvertGroupToSCIM(group, h.getBaseURL(c))
	c.Set("Content-Type", ContentTypeSCIM)
	return c.JSON(result)
}

func (h *Handler) ReplaceGroup(c fiber.Ctx) error {
	connection := c.Locals("scim_connection").(*model.EnterpriseConnection)
	connectionID := c.Locals("scim_connection_id").(uint64)

	groupIDStr := c.Params("groupId")
	groupID, err := strconv.ParseUint(groupIDStr, 10, 64)
	if err != nil {
		return h.sendSCIMError(c, 400, "Invalid group ID", "invalidValue")
	}

	group, err := h.service.GetGroupByID(groupID, connectionID)
	if err != nil {
		return h.sendSCIMError(c, 404, "Group not found", "noTarget")
	}

	var scimGroup SCIMGroup
	if err := c.Bind().Body(&scimGroup); err != nil {
		return h.sendSCIMError(c, 400, "Invalid request body", "invalidSyntax")
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if scimGroup.DisplayName != "" && scimGroup.DisplayName != group.DisplayName {
			tx.Model(group).Update("display_name", scimGroup.DisplayName)
		}
		return h.service.UpdateGroupMembers(tx, group, scimGroup.Members, connection)
	})

	if err != nil {
		return h.sendSCIMError(c, 500, err.Error(), "")
	}

	group, _ = h.service.GetGroupByID(groupID, connectionID)
	result := h.service.ConvertGroupToSCIM(group, h.getBaseURL(c))
	c.Set("Content-Type", ContentTypeSCIM)
	return c.JSON(result)
}

func (h *Handler) PatchGroup(c fiber.Ctx) error {
	connection := c.Locals("scim_connection").(*model.EnterpriseConnection)
	connectionID := c.Locals("scim_connection_id").(uint64)

	groupIDStr := c.Params("groupId")
	groupID, err := strconv.ParseUint(groupIDStr, 10, 64)
	if err != nil {
		return h.sendSCIMError(c, 400, "Invalid group ID", "invalidValue")
	}

	group, err := h.service.GetGroupByID(groupID, connectionID)
	if err != nil {
		return h.sendSCIMError(c, 404, "Group not found", "noTarget")
	}

	var patchOp SCIMPatchOp
	if err := c.Bind().Body(&patchOp); err != nil {
		return h.sendSCIMError(c, 400, "Invalid request body", "invalidSyntax")
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		return h.applyGroupPatchOperations(tx, group, patchOp.Operations, connection)
	})

	if err != nil {
		return h.sendSCIMError(c, 500, err.Error(), "")
	}

	// Reload group
	group, _ = h.service.GetGroupByID(groupID, connectionID)

	result := h.service.ConvertGroupToSCIM(group, h.getBaseURL(c))
	c.Set("Content-Type", ContentTypeSCIM)
	return c.JSON(result)
}

func (h *Handler) DeleteGroup(c fiber.Ctx) error {
	connectionID := c.Locals("scim_connection_id").(uint64)

	groupIDStr := c.Params("groupId")
	groupID, err := strconv.ParseUint(groupIDStr, 10, 64)
	if err != nil {
		return h.sendSCIMError(c, 400, "Invalid group ID", "invalidValue")
	}

	_, err = h.service.GetGroupByID(groupID, connectionID)
	if err != nil {
		return h.sendSCIMError(c, 404, "Group not found", "noTarget")
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		return h.service.DeleteGroup(tx, groupID)
	})

	if err != nil {
		return h.sendSCIMError(c, 500, err.Error(), "")
	}

	return c.SendStatus(204)
}

func (h *Handler) sendSCIMError(c fiber.Ctx, status int, detail, scimType string) error {
	c.Set("Content-Type", ContentTypeSCIM)
	return c.Status(status).JSON(NewSCIMError(status, detail, scimType))
}

func (h *Handler) getBaseURL(c fiber.Ctx) string {
	deployment := c.Locals("scim_deployment").(*model.Deployment)
	return fmt.Sprintf("https://%s", deployment.BackendHost)
}

func (h *Handler) applyUserPatchOperations(tx *gorm.DB, user *model.User, operations []SCIMPatchOpDef) error {
	for _, op := range operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			if err := h.applyUserReplaceOp(tx, user, op); err != nil {
				return err
			}
		case "add":
			// For user, add is similar to replace for most fields
			if err := h.applyUserReplaceOp(tx, user, op); err != nil {
				return err
			}
		case "remove":
			// Handle remove operations if needed
		}
	}
	return nil
}

func (h *Handler) applyUserReplaceOp(tx *gorm.DB, user *model.User, op SCIMPatchOpDef) error {
	path := strings.ToLower(op.Path)

	switch path {
	case "active":
		if active, ok := op.Value.(bool); ok {
			return tx.Model(user).Update("disabled", !active).Error
		}
	case "name.givenname":
		if v, ok := op.Value.(string); ok {
			return tx.Model(user).Update("first_name", v).Error
		}
	case "name.familyname":
		if v, ok := op.Value.(string); ok {
			return tx.Model(user).Update("last_name", v).Error
		}
	case "username":
		if v, ok := op.Value.(string); ok {
			return tx.Model(user).Update("username", v).Error
		}
	case "displayname":
		if v, ok := op.Value.(string); ok {
			parts := strings.SplitN(v, " ", 2)
			if err := tx.Model(user).Update("first_name", parts[0]).Error; err != nil {
				return err
			}
			if len(parts) > 1 {
				return tx.Model(user).Update("last_name", parts[1]).Error
			}
		}
	}

	return nil
}

func (h *Handler) applyGroupPatchOperations(tx *gorm.DB, group *model.SCIMGroup, operations []SCIMPatchOpDef, connection *model.EnterpriseConnection) error {
	for _, op := range operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			if strings.ToLower(op.Path) == "members" {
				members := h.parseMembers(op.Value)
				if err := h.service.UpdateGroupMembers(tx, group, members, connection); err != nil {
					return err
				}
			} else if strings.ToLower(op.Path) == "displayname" {
				if v, ok := op.Value.(string); ok {
					tx.Model(group).Update("display_name", v)
				}
			}
		case "add":
			if strings.ToLower(op.Path) == "members" {
				// Add new members to existing
				newMembers := h.parseMembers(op.Value)
				// Get existing members and append
				existingMembers := make([]SCIMMember, len(group.Members))
				for i, m := range group.Members {
					existingMembers[i] = SCIMMember{Value: fmt.Sprintf("%d", m.UserID)}
				}
				allMembers := append(existingMembers, newMembers...)
				if err := h.service.UpdateGroupMembers(tx, group, allMembers, connection); err != nil {
					return err
				}
			}
		case "remove":
			if strings.ToLower(op.Path) == "members" {
				// Remove specified members
				removeMembers := h.parseMembers(op.Value)
				removeIDs := make(map[string]bool)
				for _, m := range removeMembers {
					removeIDs[m.Value] = true
				}

				keepMembers := []SCIMMember{}
				for _, m := range group.Members {
					userIDStr := fmt.Sprintf("%d", m.UserID)
					if !removeIDs[userIDStr] {
						keepMembers = append(keepMembers, SCIMMember{Value: userIDStr})
					}
				}
				if err := h.service.UpdateGroupMembers(tx, group, keepMembers, connection); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (h *Handler) parseMembers(value any) []SCIMMember {
	var members []SCIMMember

	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				member := SCIMMember{}
				if val, exists := m["value"]; exists {
					member.Value = fmt.Sprintf("%v", val)
				}
				if display, exists := m["display"]; exists {
					member.Display = fmt.Sprintf("%v", display)
				}
				members = append(members, member)
			}
		}
	case []SCIMMember:
		members = v
	}

	return members
}
