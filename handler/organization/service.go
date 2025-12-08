package organization

import (
	"fmt"
	"mime/multipart"
	"path/filepath"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler/scim"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/service"
	"gorm.io/gorm"
)

var (
	orgManagementPermissions = map[string]bool{
		"organization:admin":  true,
		"organization:manage": true,
	}

	orgOwnerPermissions = map[string]bool{
		"organization:admin": true,
	}
)

type OrgService struct {
	s3   *service.S3Service
	db   *gorm.DB
	nats *service.NatsService
	scim *scim.SCIMService
}

func NewOrgService() *OrgService {
	natsService, err := service.NewNatsService()
	if err != nil {
		// Log error and panic - NATS is required for invitations
		panic(fmt.Sprintf("Failed to initialize NATS service: %v", err))
	}

	return &OrgService{
		s3:   service.NewS3Service(),
		db:   database.Connection,
		nats: natsService,
		scim: scim.NewSCIMService(),
	}
}

func (s *OrgService) uploadOrganizationImage(orgID uint64, file *multipart.FileHeader) (string, error) {
	reader, err := file.Open()
	if err != nil {
		return "", err
	}

	ext := filepath.Ext(file.Filename)

	return s.s3.UploadToCdn(fmt.Sprintf("organizations/%d.%s", orgID, ext), reader)
}

func (s *OrgService) hasPermission(membership model.OrganizationMembership, requiredPermissions map[string]bool) bool {
	for _, role := range membership.Roles {
		for _, permission := range role.Permissions {
			if requiredPermissions[permission] {
				return true
			}
		}
	}
	return false
}

func (s *OrgService) getSCIMService() *scim.SCIMService {
	return s.scim
}
