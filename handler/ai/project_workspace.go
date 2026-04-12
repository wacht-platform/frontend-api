package ai

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
)

func projectWorkspaceStoragePrefix(deploymentID, projectID uint64) string {
	return fmtStorageKeyPrefix(
		strconv.FormatUint(deploymentID, 10),
		strconv.FormatUint(projectID, 10),
	)
}

func (s *Service) uploadActorProjectWorkspaceFiles(
	deploymentID, actorID, projectID uint64,
	files []*multipart.FileHeader,
) ([]UploadedProjectWorkspaceFile, error) {
	if len(files) == 0 {
		return []UploadedProjectWorkspaceFile{}, nil
	}

	if _, err := s.GetActorProject(deploymentID, actorID, projectID); err != nil {
		return nil, err
	}

	storage, err := resolveDeploymentAgentStorage(deploymentID)
	if err != nil {
		return nil, err
	}

	results := make([]UploadedProjectWorkspaceFile, 0, len(files))
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			return nil, err
		}

		data, readErr := io.ReadAll(file)
		closeErr := file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}

		safeFilename, err := sanitizeUploadFilename(fileHeader.Filename)
		if err != nil {
			return nil, err
		}

		relativePath := filepath.ToSlash(filepath.Join("uploads", strconv.FormatUint(idgen.NextID(), 10)+"_"+safeFilename))

		contentType := fileHeader.Header.Get("Content-Type")
		if contentType == "" || contentType == "application/octet-stream" {
			contentType = http.DetectContentType(data)
		}

		_, err = storage.s3Client.PutObject(&s3.PutObjectInput{
			Bucket:      aws.String(storage.bucket),
			Key:         aws.String(storage.objectKey(projectWorkspaceStoragePrefix(deploymentID, projectID) + relativePath)),
			Body:        bytes.NewReader(data),
			ContentType: aws.String(contentType),
		})
		if err != nil {
			return nil, err
		}

		results = append(results, UploadedProjectWorkspaceFile{
			Path:         "/project/" + relativePath,
			Name:         filepath.Base(relativePath),
			OriginalName: fileHeader.Filename,
			MimeType:     contentType,
			SizeBytes:    uint64(len(data)),
		})
	}

	return results, nil
}
