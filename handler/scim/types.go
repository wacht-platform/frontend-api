package scim

// SCIM 2.0 Types following RFC 7643 and RFC 7644
// https://datatracker.ietf.org/doc/html/rfc7643
// https://datatracker.ietf.org/doc/html/rfc7644

const (
	// Schema URIs
	SchemaUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup                 = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatchOp               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema                = "urn:ietf:params:scim:schemas:core:2.0:Schema"

	// Content Types
	ContentTypeSCIM = "application/scim+json"
	ContentTypeJSON = "application/json"
)

// SCIMMeta contains resource metadata
type SCIMMeta struct {
	ResourceType string `json:"resourceType,omitempty"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
	Version      string `json:"version,omitempty"`
}

// SCIMName represents the components of a user's name
type SCIMName struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

// SCIMEmail represents an email address
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMPhoneNumber represents a phone number
type SCIMPhoneNumber struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMUser represents a SCIM User resource
type SCIMUser struct {
	Schemas      []string          `json:"schemas"`
	ID           string            `json:"id,omitempty"`
	ExternalId   string            `json:"externalId,omitempty"`
	Meta         *SCIMMeta         `json:"meta,omitempty"`
	UserName     string            `json:"userName"`
	Name         *SCIMName         `json:"name,omitempty"`
	DisplayName  string            `json:"displayName,omitempty"`
	NickName     string            `json:"nickName,omitempty"`
	ProfileUrl   string            `json:"profileUrl,omitempty"`
	Title        string            `json:"title,omitempty"`
	UserType     string            `json:"userType,omitempty"`
	Emails       []SCIMEmail       `json:"emails,omitempty"`
	PhoneNumbers []SCIMPhoneNumber `json:"phoneNumbers,omitempty"`
	Active       *bool             `json:"active,omitempty"`
	Password     string            `json:"password,omitempty"`
	Groups       []SCIMMember      `json:"groups,omitempty"`
}

// SCIMMember represents a group member or a user's group membership
type SCIMMember struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// SCIMGroup represents a SCIM Group resource
type SCIMGroup struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id,omitempty"`
	ExternalId  string       `json:"externalId,omitempty"`
	Meta        *SCIMMeta    `json:"meta,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []SCIMMember `json:"members,omitempty"`
}

// SCIMListResponse represents a SCIM list response
type SCIMListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	ItemsPerPage int      `json:"itemsPerPage,omitempty"`
	StartIndex   int      `json:"startIndex,omitempty"`
	Resources    []any    `json:"Resources"`
}

// SCIMError represents a SCIM error response
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   int      `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
}

// SCIMPatchOp represents a SCIM PATCH operation
type SCIMPatchOp struct {
	Schemas    []string         `json:"schemas"`
	Operations []SCIMPatchOpDef `json:"Operations"`
}

// SCIMPatchOpDef represents a single PATCH operation
type SCIMPatchOpDef struct {
	Op    string `json:"op"`    // "add", "remove", "replace"
	Path  string `json:"path"`  // e.g., "members", "displayName"
	Value any    `json:"value"` // The value to add/replace
}

// ServiceProviderConfig represents SCIM service provider capabilities
type ServiceProviderConfig struct {
	Schemas               []string          `json:"schemas"`
	DocumentationUri      string            `json:"documentationUri,omitempty"`
	Patch                 SPConfigSupported `json:"patch"`
	Bulk                  SPConfigBulk      `json:"bulk"`
	Filter                SPConfigFilter    `json:"filter"`
	ChangePassword        SPConfigSupported `json:"changePassword"`
	Sort                  SPConfigSupported `json:"sort"`
	Etag                  SPConfigSupported `json:"etag"`
	AuthenticationSchemes []SPAuthScheme    `json:"authenticationSchemes"`
	Meta                  *SCIMMeta         `json:"meta,omitempty"`
}

// SPConfigSupported indicates if a feature is supported
type SPConfigSupported struct {
	Supported bool `json:"supported"`
}

// SPConfigBulk indicates bulk operation support
type SPConfigBulk struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

// SPConfigFilter indicates filter support
type SPConfigFilter struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// SPAuthScheme describes an authentication scheme
type SPAuthScheme struct {
	Type             string `json:"type"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	SpecUri          string `json:"specUri,omitempty"`
	DocumentationUri string `json:"documentationUri,omitempty"`
	Primary          bool   `json:"primary,omitempty"`
}

// ResourceType represents a SCIM resource type
type ResourceType struct {
	Schemas          []string          `json:"schemas"`
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Endpoint         string            `json:"endpoint"`
	Description      string            `json:"description,omitempty"`
	Schema           string            `json:"schema"`
	SchemaExtensions []SchemaExtension `json:"schemaExtensions,omitempty"`
	Meta             *SCIMMeta         `json:"meta,omitempty"`
}

// SchemaExtension represents a schema extension
type SchemaExtension struct {
	Schema   string `json:"schema"`
	Required bool   `json:"required"`
}

// Helper constructors

// NewSCIMError creates a new SCIM error response
func NewSCIMError(status int, detail string, scimType string) *SCIMError {
	return &SCIMError{
		Schemas:  []string{SchemaError},
		Detail:   detail,
		Status:   status,
		ScimType: scimType,
	}
}

// NewSCIMListResponse creates a new SCIM list response
func NewSCIMListResponse(resources []any, totalResults, startIndex, itemsPerPage int) *SCIMListResponse {
	return &SCIMListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: totalResults,
		ItemsPerPage: itemsPerPage,
		StartIndex:   startIndex,
		Resources:    resources,
	}
}

// GetPrimaryEmail returns the primary email from a list of emails
func (u *SCIMUser) GetPrimaryEmail() string {
	for _, email := range u.Emails {
		if email.Primary {
			return email.Value
		}
	}
	// If no primary, return the first one
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	// Fall back to userName if it looks like an email
	return u.UserName
}

// IsActive returns true if the user is active
func (u *SCIMUser) IsActive() bool {
	if u.Active == nil {
		return true // Default to active if not specified
	}
	return *u.Active
}
