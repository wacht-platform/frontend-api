package organization

import (
	"fmt"
	"mime/multipart"
	"path/filepath"

	"github.com/ilabs/wacht-fe/service"
)

type OrgService struct {
	s3 *service.S3Service
}

func NewOrgService() *OrgService {
	return &OrgService{
		s3: service.NewS3Service(),
	}
}

func (s *OrgService) UploadOrganizationImage(orgID uint, file *multipart.FileHeader) (string, error) {
	reader, err := file.Open()
	if err != nil {
		return "", err
	}

	ext := filepath.Ext(file.Filename)

	return s.s3.UploadToCdn(fmt.Sprintf("organizations/%d.%s", orgID, ext), reader)
}
