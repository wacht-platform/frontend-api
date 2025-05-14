package workspace

import (
	"fmt"
	"mime/multipart"
	"path/filepath"

	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/service"
	"gorm.io/gorm"
)

var (
	workspaceAdminPermissions = map[string]bool{
		"workspace:admin": true,
	}
	workspaceManagementPermissions = map[string]bool{
		"workspace:admin":  true,
		"workspace:manage": true,
	}
	workspaceDeletePermissions = map[string]bool{
		"workspace:admin": true,
	}
)

type WorkspaceService struct {
	s3 *service.S3Service
	db *gorm.DB
}

func NewWorkspaceService() *WorkspaceService {
	return &WorkspaceService{
		s3: service.NewS3Service(),
	}
}

func (s *WorkspaceService) hasWorkspacePermission(membership model.WorkspaceMembership, requiredPermissions map[string]bool) bool {
	if len(membership.Role) == 0 {
		return false
	}
	for _, role := range membership.Role {
		for _, p := range role.Permissions {
			if requiredPermissions[p] {
				return true
			}
		}
	}
	return false
}

func (s *WorkspaceService) uploadWorkspaceImage(workspaceID uint64, file *multipart.FileHeader) (string, error) {
	reader, err := file.Open()
	if err != nil {
		return "", err
	}

	ext := filepath.Ext(file.Filename)

	return s.s3.UploadToCdn(fmt.Sprintf("workspace/%d.%s", workspaceID, ext), reader)
}
