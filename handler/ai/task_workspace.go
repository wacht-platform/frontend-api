package ai

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
	"gorm.io/gorm"
)

const (
	maxTaskWorkspacePreviewBytes       = 256 * 1024
	maxTaskWorkspaceBinaryPreviewBytes = 8 * 1024 * 1024
	maxTaskWorkspaceUploadBytes        = 64 * 1024 * 1024
	maxTaskWorkspaceReadBytes          = 64 * 1024 * 1024
)

var (
	errTaskWorkspacePathRequired            = errors.New("path required")
	errTaskWorkspacePathTraversalNotAllowed = errors.New("path traversal not allowed")
	errTaskWorkspacePathOutsideRoots        = errors.New("path must be inside workspace or uploads")
	errTaskWorkspaceRequestedDirectory      = errors.New("requested path is a directory")
	errTaskWorkspaceFileTooLarge            = errors.New("file too large")
)

type TaskWorkspaceFileEntry struct {
	Path       string     `json:"path"`
	Name       string     `json:"name"`
	IsDir      bool       `json:"is_dir"`
	SizeBytes  *uint64    `json:"size_bytes,omitempty"`
	ModifiedAt *time.Time `json:"modified_at,omitempty"`
}

type TaskWorkspaceListing struct {
	Exists bool                     `json:"exists"`
	Files  []TaskWorkspaceFileEntry `json:"files"`
	Mounts []TaskWorkspaceMount     `json:"mounts,omitempty"`
}

type TaskWorkspaceMount struct {
	MountPath   string  `json:"mount_path"`
	Mode        string  `json:"mode"`
	Description *string `json:"description,omitempty"`
}

type TaskWorkspaceFileContent struct {
	Path          string `json:"path"`
	Name          string `json:"name"`
	MimeType      string `json:"mime_type"`
	IsText        bool   `json:"is_text"`
	SizeBytes     uint64 `json:"size_bytes"`
	Truncated     bool   `json:"truncated"`
	Content       string `json:"content,omitempty"`
	ContentBase64 string `json:"content_base64,omitempty"`
}

func threadWorkspaceStoragePrefix(deploymentID, threadID uint64) string {
	return fmtStorageKeyPrefix(
		strconv.FormatUint(deploymentID, 10),
		"persistent",
		strconv.FormatUint(threadID, 10),
		"workspace",
	)
}

func threadUploadsStoragePrefix(deploymentID, threadID uint64) string {
	return fmtStorageKeyPrefix(
		strconv.FormatUint(deploymentID, 10),
		"persistent",
		strconv.FormatUint(threadID, 10),
		"uploads",
	)
}

func taskWorkspaceStoragePrefix(deploymentID, projectID uint64, taskKey string) string {
	return fmtStorageKeyPrefix(
		strconv.FormatUint(deploymentID, 10),
		strconv.FormatUint(projectID, 10),
		"tasks",
		taskKey,
	)
}

func fmtStorageKeyPrefix(parts ...string) string {
	return strings.Join(parts, "/") + "/"
}

func sanitizeTaskWorkspaceRelativePath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errTaskWorkspacePathRequired
	}

	normalized := strings.ReplaceAll(trimmed, "\\", "/")
	cleaned := pathClean(normalized)
	if cleaned == "." || cleaned == "/" || cleaned == "" {
		return "", errTaskWorkspacePathRequired
	}
	if strings.HasPrefix(cleaned, "../") || cleaned == ".." || strings.HasPrefix(cleaned, "/") {
		return "", errTaskWorkspacePathTraversalNotAllowed
	}
	return cleaned, nil
}

func pathClean(value string) string {
	return filepath.ToSlash(filepath.Clean(value))
}

func isTextMimeType(mimeType string) bool {
	return strings.HasPrefix(mimeType, "text/") ||
		strings.Contains(mimeType, "typescript") ||
		strings.Contains(mimeType, "python") ||
		strings.Contains(mimeType, "json") ||
		strings.Contains(mimeType, "javascript") ||
		strings.Contains(mimeType, "xml") ||
		strings.Contains(mimeType, "yaml")
}

func workspaceFileExtension(path string) string {
	name := filepath.Base(path)
	dot := strings.LastIndex(name, ".")
	if dot < 0 || dot == len(name)-1 {
		return ""
	}
	return strings.ToLower(name[dot+1:])
}

func isDocxFile(path string, mimeType string) bool {
	return strings.EqualFold(workspaceFileExtension(path), "docx") ||
		strings.Contains(strings.ToLower(mimeType), "wordprocessingml")
}

func isPptxFile(path string, mimeType string) bool {
	return strings.EqualFold(workspaceFileExtension(path), "pptx") ||
		strings.Contains(strings.ToLower(mimeType), "presentationml")
}

func isPreviewableTextFile(path string, mimeType string) bool {
	ext := workspaceFileExtension(path)

	nonTextExtensions := map[string]struct{}{
		"doc": {}, "docx": {}, "ppt": {}, "pptx": {}, "xls": {}, "xlsx": {},
		"pdf": {}, "zip": {}, "gz": {}, "tar": {}, "7z": {}, "rar": {},
		"jar": {}, "war": {}, "bin": {},
	}
	if _, found := nonTextExtensions[ext]; found {
		return false
	}

	textExtensions := map[string]struct{}{
		"txt": {}, "md": {}, "mdx": {}, "markdown": {}, "json": {}, "jsonc": {},
		"js": {}, "jsx": {}, "ts": {}, "tsx": {}, "mts": {}, "cts": {}, "mjs": {}, "cjs": {},
		"py": {}, "rb": {}, "php": {}, "java": {}, "kt": {}, "kts": {}, "go": {}, "rs": {},
		"c": {}, "cc": {}, "cpp": {}, "cxx": {}, "h": {}, "hpp": {}, "swift": {},
		"sh": {}, "bash": {}, "zsh": {}, "fish": {}, "ps1": {}, "sql": {},
		"html": {}, "htm": {}, "css": {}, "scss": {}, "less": {},
		"xml": {}, "svg": {}, "yaml": {}, "yml": {}, "toml": {}, "ini": {}, "cfg": {}, "conf": {}, "env": {}, "log": {},
	}
	if _, found := textExtensions[ext]; found {
		return true
	}

	return isTextMimeType(mimeType)
}

func isBinaryPreviewableFile(path string, mimeType string) bool {
	return isPdfFile(path, mimeType) || isImageMimeType(mimeType)
}

func isPdfFile(path string, mimeType string) bool {
	return strings.EqualFold(workspaceFileExtension(path), "pdf") ||
		strings.Contains(strings.ToLower(mimeType), "pdf")
}

func isImageMimeType(mimeType string) bool {
	return strings.HasPrefix(strings.ToLower(mimeType), "image/")
}

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func extractXMLText(data []byte, breakOnParagraph bool) string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var builder strings.Builder
	var currentParagraph strings.Builder

	flushParagraph := func() {
		text := strings.TrimSpace(currentParagraph.String())
		if text == "" {
			currentParagraph.Reset()
			return
		}
		if builder.Len() > 0 {
			builder.WriteString("\n\n")
		}
		builder.WriteString(text)
		currentParagraph.Reset()
	}

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return strings.TrimSpace(builder.String())
		}

		switch element := token.(type) {
		case xml.CharData:
			text := strings.TrimSpace(string(element))
			if text == "" {
				continue
			}
			if currentParagraph.Len() > 0 {
				currentParagraph.WriteByte(' ')
			}
			currentParagraph.WriteString(text)
		case xml.EndElement:
			if breakOnParagraph && strings.EqualFold(element.Name.Local, "p") {
				flushParagraph()
			}
		}
	}

	flushParagraph()
	return strings.TrimSpace(builder.String())
}

var pptxSlideRe = regexp.MustCompile(`slide(\d+)\.xml$`)

func extractDocxPreview(body []byte) string {
	readerAt := bytes.NewReader(body)
	archive, err := zip.NewReader(readerAt, int64(len(body)))
	if err != nil {
		return ""
	}

	for _, file := range archive.File {
		if file.Name != "word/document.xml" {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return ""
		}
		defer rc.Close()
		data, err := io.ReadAll(rc)
		if err != nil {
			return ""
		}
		return extractXMLText(data, true)
	}

	return ""
}

func slideNumber(name string) int {
	match := pptxSlideRe.FindStringSubmatch(name)
	if len(match) != 2 {
		return 1<<30 - 1
	}
	value, err := strconv.Atoi(match[1])
	if err != nil {
		return 1<<30 - 1
	}
	return value
}

func extractPptxPreview(body []byte) string {
	readerAt := bytes.NewReader(body)
	archive, err := zip.NewReader(readerAt, int64(len(body)))
	if err != nil {
		return ""
	}

	slides := make([]*zip.File, 0)
	for _, file := range archive.File {
		if pptxSlideRe.MatchString(file.Name) && strings.HasPrefix(file.Name, "ppt/slides/") {
			slides = append(slides, file)
		}
	}

	sort.Slice(slides, func(i, j int) bool {
		return slideNumber(slides[i].Name) < slideNumber(slides[j].Name)
	})

	var sections []string
	for index, file := range slides {
		rc, err := file.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		text := extractXMLText(data, false)
		text = strings.TrimSpace(text)
		header := "## Slide " + strconv.Itoa(index+1)
		if text == "" {
			sections = append(sections, header)
			continue
		}
		lines := strings.FieldsFunc(text, func(r rune) bool {
			return r == '\n' || r == '\r'
		})
		if len(lines) == 0 {
			sections = append(sections, header)
			continue
		}
		title := strings.TrimSpace(lines[0])
		body := strings.Join(lines[1:], "\n")
		if title != "" {
			header += ": " + title
		}
		if strings.TrimSpace(body) != "" {
			sections = append(sections, header+"\n"+body)
		} else {
			sections = append(sections, header)
		}
	}

	return strings.Join(sections, "\n\n")
}

func extractOfficePreview(path string, mimeType string, body []byte) string {
	if isDocxFile(path, mimeType) {
		return extractDocxPreview(body)
	}
	if isPptxFile(path, mimeType) {
		return extractPptxPreview(body)
	}
	return ""
}

func trimToValidUTF8Prefix(data []byte) []byte {
	for len(data) > 0 && !utf8.Valid(data) {
		data = data[:len(data)-1]
	}
	return data
}

func isS3NotFound(err error) bool {
	if err == nil {
		return false
	}
	var awsErr awserr.Error
	if errors.As(err, &awsErr) {
		code := awsErr.Code()
		return code == s3.ErrCodeNoSuchKey || code == "NotFound" || code == "NoSuchKey"
	}
	return false
}

func listWorkspaceDirectoryFromStorage(
	storage *deploymentAgentStorage,
	basePrefix string,
	relativePath string,
) (*TaskWorkspaceListing, error) {
	cleanedRelativePath, err := sanitizeOptionalTaskWorkspaceRelativePath(relativePath)
	if err != nil {
		return nil, err
	}

	baseKeyPrefix := storage.objectKey(basePrefix)
	targetPrefix := basePrefix
	if cleanedRelativePath != "" {
		targetPrefix += cleanedRelativePath + "/"
	}
	targetKeyPrefix := storage.objectKey(targetPrefix)
	entries := make([]TaskWorkspaceFileEntry, 0)
	var continuationToken *string

	for {
		result, err := storage.s3Client.ListObjectsV2(&s3.ListObjectsV2Input{
			Bucket:            aws.String(storage.bucket),
			Prefix:            aws.String(targetKeyPrefix),
			Delimiter:         aws.String("/"),
			ContinuationToken: continuationToken,
		})
		if err != nil {
			return nil, err
		}

		for _, prefix := range result.CommonPrefixes {
			if prefix.Prefix == nil {
				continue
			}
			relativeEntryPath := strings.TrimSuffix(strings.TrimPrefix(*prefix.Prefix, baseKeyPrefix), "/")
			if relativeEntryPath == "" {
				continue
			}
			entries = append(entries, TaskWorkspaceFileEntry{
				Path:  relativeEntryPath,
				Name:  filepath.Base(relativeEntryPath),
				IsDir: true,
			})
		}

		for _, obj := range result.Contents {
			if obj.Key == nil {
				continue
			}
			key := *obj.Key
			if key == targetKeyPrefix || strings.HasSuffix(key, "/") {
				continue
			}

			relativeEntryPath := strings.TrimPrefix(key, baseKeyPrefix)
			if relativeEntryPath == "" {
				continue
			}

			entry := TaskWorkspaceFileEntry{
				Path:  relativeEntryPath,
				Name:  filepath.Base(relativeEntryPath),
				IsDir: false,
			}
			if obj.Size != nil {
				size := uint64(*obj.Size)
				entry.SizeBytes = &size
			}
			if obj.LastModified != nil {
				modifiedAt := *obj.LastModified
				entry.ModifiedAt = &modifiedAt
			}
			entries = append(entries, entry)
		}

		if result.IsTruncated == nil || !*result.IsTruncated {
			break
		}
		continuationToken = result.NextContinuationToken
	}

	sort.Slice(entries, func(i, j int) bool {
		left := strings.ToLower(entries[i].Path)
		right := strings.ToLower(entries[j].Path)
		if left == right {
			if entries[i].IsDir == entries[j].IsDir {
				return entries[i].Name < entries[j].Name
			}
			return entries[i].IsDir && !entries[j].IsDir
		}
		return left < right
	})

	exists := cleanedRelativePath == "" || len(entries) > 0
	return &TaskWorkspaceListing{
		Exists: exists,
		Files:  entries,
	}, nil
}

// getWorkspaceFileStreamFromStorage returns the S3 object body as a stream
// (caller owns closing). Used by download endpoints to avoid buffering the
// whole file into memory before sending the response.
func getWorkspaceFileStreamFromStorage(
	storage *deploymentAgentStorage,
	basePrefix string,
	relativePath string,
) (io.ReadCloser, int64, string, error) {
	cleanedRelativePath, err := sanitizeTaskWorkspaceRelativePath(relativePath)
	if err != nil {
		return nil, 0, "", err
	}

	key := storage.objectKey(basePrefix + cleanedRelativePath)
	result, err := storage.s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(storage.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, 0, "", err
	}

	var size int64
	if result.ContentLength != nil {
		size = *result.ContentLength
		if size > maxTaskWorkspaceReadBytes {
			result.Body.Close()
			return nil, 0, "", errTaskWorkspaceFileTooLarge
		}
	}

	mimeType := "application/octet-stream"
	if result.ContentType != nil && strings.TrimSpace(*result.ContentType) != "" {
		mimeType = *result.ContentType
	} else if ext := filepath.Ext(cleanedRelativePath); ext != "" {
		if guess := mime.TypeByExtension(ext); guess != "" {
			mimeType = guess
		}
	}

	return result.Body, size, mimeType, nil
}

func getBoardItemTaskWorkspaceFileStreamFromStorage(
	storage *deploymentAgentStorage,
	deploymentID, projectID uint64,
	taskKey, relativePath string,
) (io.ReadCloser, int64, string, error) {
	return getWorkspaceFileStreamFromStorage(
		storage,
		taskWorkspaceStoragePrefix(deploymentID, projectID, taskKey),
		relativePath,
	)
}

func getThreadFilesystemFileStreamFromStorage(
	storage *deploymentAgentStorage,
	deploymentID, threadID uint64,
	relativePath string,
) (io.ReadCloser, int64, string, error) {
	cleanedRelativePath, err := sanitizeTaskWorkspaceRelativePath(relativePath)
	if err != nil {
		return nil, 0, "", err
	}

	switch {
	case cleanedRelativePath == "workspace", cleanedRelativePath == "uploads":
		return nil, 0, "", errTaskWorkspaceRequestedDirectory
	case strings.HasPrefix(cleanedRelativePath, "workspace/"):
		return getWorkspaceFileStreamFromStorage(
			storage,
			threadWorkspaceStoragePrefix(deploymentID, threadID),
			strings.TrimPrefix(cleanedRelativePath, "workspace/"),
		)
	case strings.HasPrefix(cleanedRelativePath, "uploads/"):
		return getWorkspaceFileStreamFromStorage(
			storage,
			threadUploadsStoragePrefix(deploymentID, threadID),
			strings.TrimPrefix(cleanedRelativePath, "uploads/"),
		)
	default:
		return nil, 0, "", errTaskWorkspacePathOutsideRoots
	}
}

func getWorkspaceFileBytesFromStorage(
	storage *deploymentAgentStorage,
	basePrefix string,
	relativePath string,
) ([]byte, string, error) {
	cleanedRelativePath, err := sanitizeTaskWorkspaceRelativePath(relativePath)
	if err != nil {
		return nil, "", err
	}

	key := storage.objectKey(basePrefix + cleanedRelativePath)
	result, err := storage.s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(storage.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, "", err
	}
	defer result.Body.Close()

	if result.ContentLength != nil && *result.ContentLength > maxTaskWorkspaceReadBytes {
		return nil, "", errTaskWorkspaceFileTooLarge
	}

	body, err := io.ReadAll(io.LimitReader(result.Body, maxTaskWorkspaceReadBytes+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > maxTaskWorkspaceReadBytes {
		return nil, "", errTaskWorkspaceFileTooLarge
	}

	mimeType := http.DetectContentType(body)
	if result.ContentType != nil && strings.TrimSpace(*result.ContentType) != "" {
		mimeType = *result.ContentType
	}

	return body, mimeType, nil
}

func getWorkspaceFileContentFromStorage(
	storage *deploymentAgentStorage,
	basePrefix string,
	relativePath string,
) (*TaskWorkspaceFileContent, error) {
	body, mimeType, err := getWorkspaceFileBytesFromStorage(storage, basePrefix, relativePath)
	if err != nil {
		return nil, err
	}

	cleanedRelativePath, err := sanitizeTaskWorkspaceRelativePath(relativePath)
	if err != nil {
		return nil, err
	}

	sizeBytes := uint64(len(body))
	previewBytes := body
	truncated := false
	if len(previewBytes) > maxTaskWorkspacePreviewBytes {
		previewBytes = previewBytes[:maxTaskWorkspacePreviewBytes]
		truncated = true
	}

	isText := utf8.Valid(previewBytes) && isPreviewableTextFile(cleanedRelativePath, mimeType)
	content := ""
	contentBase64 := ""
	if isText {
		content = string(trimToValidUTF8Prefix(previewBytes))
	} else if officePreview := extractOfficePreview(cleanedRelativePath, mimeType, body); officePreview != "" {
		isText = true
		content = officePreview
	} else if isBinaryPreviewableFile(cleanedRelativePath, mimeType) && len(body) <= maxTaskWorkspaceBinaryPreviewBytes {
		contentBase64 = encodeBase64(body)
	}

	return &TaskWorkspaceFileContent{
		Path:          cleanedRelativePath,
		Name:          filepath.Base(cleanedRelativePath),
		MimeType:      mimeType,
		IsText:        isText,
		SizeBytes:     sizeBytes,
		Truncated:     truncated,
		Content:       content,
		ContentBase64: contentBase64,
	}, nil
}

func listTaskWorkspaceFilesFromStorage(
	storage *deploymentAgentStorage,
	deploymentID, projectID uint64,
	taskKey string,
	relativePath string,
) (*TaskWorkspaceListing, error) {
	return listWorkspaceDirectoryFromStorage(
		storage,
		taskWorkspaceStoragePrefix(deploymentID, projectID, taskKey),
		relativePath,
	)
}

func getTaskWorkspaceFileContentFromStorage(
	storage *deploymentAgentStorage,
	deploymentID, projectID uint64,
	taskKey, relativePath string,
) (*TaskWorkspaceFileContent, error) {
	return getWorkspaceFileContentFromStorage(
		storage,
		taskWorkspaceStoragePrefix(deploymentID, projectID, taskKey),
		relativePath,
	)
}

func sanitizeOptionalTaskWorkspaceRelativePath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	return sanitizeTaskWorkspaceRelativePath(trimmed)
}

func prefixListingPaths(prefix string, listing *TaskWorkspaceListing) *TaskWorkspaceListing {
	if listing == nil {
		return &TaskWorkspaceListing{
			Exists: false,
			Files:  []TaskWorkspaceFileEntry{},
		}
	}

	entries := make([]TaskWorkspaceFileEntry, 0, len(listing.Files))
	for _, entry := range listing.Files {
		prefixed := entry
		prefixed.Path = pathClean(filepath.ToSlash(filepath.Join(prefix, entry.Path)))
		entries = append(entries, prefixed)
	}

	return &TaskWorkspaceListing{
		Exists: listing.Exists,
		Files:  entries,
	}
}

func listThreadFilesystemEntriesFromStorage(
	storage *deploymentAgentStorage,
	deploymentID, threadID uint64,
	relativePath string,
) (*TaskWorkspaceListing, error) {
	cleanedRelativePath, err := sanitizeOptionalTaskWorkspaceRelativePath(relativePath)
	if err != nil {
		return nil, err
	}

	if cleanedRelativePath == "" {
		return &TaskWorkspaceListing{
			Exists: true,
			Files: []TaskWorkspaceFileEntry{
				{Path: "uploads", Name: "uploads", IsDir: true},
				{Path: "workspace", Name: "workspace", IsDir: true},
			},
		}, nil
	}

	switch {
	case cleanedRelativePath == "workspace":
		listing, err := listWorkspaceDirectoryFromStorage(
			storage,
			threadWorkspaceStoragePrefix(deploymentID, threadID),
			"",
		)
		if err != nil {
			return nil, err
		}
		return prefixListingPaths("workspace", listing), nil
	case cleanedRelativePath == "uploads":
		listing, err := listWorkspaceDirectoryFromStorage(
			storage,
			threadUploadsStoragePrefix(deploymentID, threadID),
			"",
		)
		if err != nil {
			return nil, err
		}
		return prefixListingPaths("uploads", listing), nil
	case strings.HasPrefix(cleanedRelativePath, "workspace/"):
		listing, err := listWorkspaceDirectoryFromStorage(
			storage,
			threadWorkspaceStoragePrefix(deploymentID, threadID),
			strings.TrimPrefix(cleanedRelativePath, "workspace/"),
		)
		if err != nil {
			return nil, err
		}
		return prefixListingPaths("workspace", listing), nil
	case strings.HasPrefix(cleanedRelativePath, "uploads/"):
		listing, err := listWorkspaceDirectoryFromStorage(
			storage,
			threadUploadsStoragePrefix(deploymentID, threadID),
			strings.TrimPrefix(cleanedRelativePath, "uploads/"),
		)
		if err != nil {
			return nil, err
		}
		return prefixListingPaths("uploads", listing), nil
	default:
		return nil, errors.New("path must be inside workspace or uploads")
	}
}

func getBoardItemTaskWorkspaceFileBytesFromStorage(
	storage *deploymentAgentStorage,
	deploymentID, projectID uint64,
	taskKey, relativePath string,
) ([]byte, string, error) {
	return getWorkspaceFileBytesFromStorage(
		storage,
		taskWorkspaceStoragePrefix(deploymentID, projectID, taskKey),
		relativePath,
	)
}

func getThreadFilesystemFileBytesFromStorage(
	storage *deploymentAgentStorage,
	deploymentID, threadID uint64,
	relativePath string,
) ([]byte, string, error) {
	cleanedRelativePath, err := sanitizeTaskWorkspaceRelativePath(relativePath)
	if err != nil {
		return nil, "", err
	}

	switch {
	case cleanedRelativePath == "workspace", cleanedRelativePath == "uploads":
		return nil, "", errTaskWorkspaceRequestedDirectory
	case strings.HasPrefix(cleanedRelativePath, "workspace/"):
		return getWorkspaceFileBytesFromStorage(
			storage,
			threadWorkspaceStoragePrefix(deploymentID, threadID),
			strings.TrimPrefix(cleanedRelativePath, "workspace/"),
		)
	case strings.HasPrefix(cleanedRelativePath, "uploads/"):
		return getWorkspaceFileBytesFromStorage(
			storage,
			threadUploadsStoragePrefix(deploymentID, threadID),
			strings.TrimPrefix(cleanedRelativePath, "uploads/"),
		)
	default:
		return nil, "", errTaskWorkspacePathOutsideRoots
	}
}

func (s *Service) ListBoardItemTaskWorkspaceFiles(deploymentID, actorID, projectID, itemID uint64, relativePath string, includeArchived bool) (*TaskWorkspaceListing, error) {
	item, err := s.GetAuthorizedBoardItem(deploymentID, actorID, itemID, includeArchived)
	if err != nil {
		return nil, err
	}
	board, err := s.GetProjectBoardByID(deploymentID, actorID, item.BoardID)
	if err != nil {
		return nil, err
	}
	if board.ProjectID != projectID {
		return nil, gorm.ErrRecordNotFound
	}

	storage, err := resolveDeploymentAgentStorage(deploymentID)
	if err != nil {
		return nil, err
	}

	listing, err := listTaskWorkspaceFilesFromStorage(storage, deploymentID, board.ProjectID, item.TaskKey, relativePath)
	if err != nil {
		return nil, err
	}
	listing.Mounts = parseBoardItemMounts(item.Mounts)
	return listing, nil
}

func parseBoardItemMounts(raw json.RawMessage) []TaskWorkspaceMount {
	if len(raw) == 0 {
		return []TaskWorkspaceMount{}
	}
	var entries []struct {
		MountPath   string  `json:"mount_path"`
		Mode        string  `json:"mode"`
		Description *string `json:"description,omitempty"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return []TaskWorkspaceMount{}
	}
	out := make([]TaskWorkspaceMount, 0, len(entries))
	for _, e := range entries {
		out = append(out, TaskWorkspaceMount{
			MountPath:   e.MountPath,
			Mode:        e.Mode,
			Description: e.Description,
		})
	}
	return out
}

func (s *Service) GetBoardItemTaskWorkspaceFileContent(deploymentID, actorID, projectID, itemID uint64, relativePath string, includeArchived bool) (*TaskWorkspaceFileContent, error) {
	item, err := s.GetAuthorizedBoardItem(deploymentID, actorID, itemID, includeArchived)
	if err != nil {
		return nil, err
	}
	board, err := s.GetProjectBoardByID(deploymentID, actorID, item.BoardID)
	if err != nil {
		return nil, err
	}
	if board.ProjectID != projectID {
		return nil, gorm.ErrRecordNotFound
	}

	storage, err := resolveDeploymentAgentStorage(deploymentID)
	if err != nil {
		return nil, err
	}

	return getTaskWorkspaceFileContentFromStorage(storage, deploymentID, board.ProjectID, item.TaskKey, relativePath)
}

// StreamBoardItemTaskWorkspaceFile is the streaming variant of
// GetBoardItemTaskWorkspaceFileBytes. The caller owns closing the returned
// ReadCloser. Use this for download endpoints that should not buffer the
// whole file in memory.
func (s *Service) StreamBoardItemTaskWorkspaceFile(deploymentID, actorID, projectID, itemID uint64, relativePath string, includeArchived bool) (io.ReadCloser, int64, string, error) {
	item, err := s.GetAuthorizedBoardItem(deploymentID, actorID, itemID, includeArchived)
	if err != nil {
		return nil, 0, "", err
	}
	board, err := s.GetProjectBoardByID(deploymentID, actorID, item.BoardID)
	if err != nil {
		return nil, 0, "", err
	}
	if board.ProjectID != projectID {
		return nil, 0, "", gorm.ErrRecordNotFound
	}

	storage, err := resolveDeploymentAgentStorage(deploymentID)
	if err != nil {
		return nil, 0, "", err
	}

	return getBoardItemTaskWorkspaceFileStreamFromStorage(storage, deploymentID, board.ProjectID, item.TaskKey, relativePath)
}

func (s *Service) GetBoardItemTaskWorkspaceFileBytes(deploymentID, actorID, projectID, itemID uint64, relativePath string, includeArchived bool) ([]byte, string, error) {
	item, err := s.GetAuthorizedBoardItem(deploymentID, actorID, itemID, includeArchived)
	if err != nil {
		return nil, "", err
	}
	board, err := s.GetProjectBoardByID(deploymentID, actorID, item.BoardID)
	if err != nil {
		return nil, "", err
	}
	if board.ProjectID != projectID {
		return nil, "", gorm.ErrRecordNotFound
	}

	storage, err := resolveDeploymentAgentStorage(deploymentID)
	if err != nil {
		return nil, "", err
	}

	return getBoardItemTaskWorkspaceFileBytesFromStorage(storage, deploymentID, board.ProjectID, item.TaskKey, relativePath)
}

func (s *Service) ListThreadFilesystemEntries(deploymentID, actorID, threadID uint64, relativePath string) (*TaskWorkspaceListing, error) {
	if _, err := s.GetThread(deploymentID, actorID, threadID); err != nil {
		return nil, err
	}

	storage, err := resolveDeploymentAgentStorage(deploymentID)
	if err != nil {
		return nil, err
	}

	return listThreadFilesystemEntriesFromStorage(storage, deploymentID, threadID, relativePath)
}

func uploadTaskWorkspaceFilesForTaskKey(
	deploymentID uint64,
	projectID uint64,
	taskKey string,
	files []*multipart.FileHeader,
) ([]UploadedTaskWorkspaceFile, error) {
	if len(files) == 0 {
		return []UploadedTaskWorkspaceFile{}, nil
	}

	storage, err := resolveDeploymentAgentStorage(deploymentID)
	if err != nil {
		return nil, err
	}

	results := make([]UploadedTaskWorkspaceFile, 0, len(files))
	for _, fileHeader := range files {
		if fileHeader.Size > maxTaskWorkspaceUploadBytes {
			return nil, fmt.Errorf("%w: %s", errTaskWorkspaceFileTooLarge, fileHeader.Filename)
		}

		file, err := fileHeader.Open()
		if err != nil {
			return nil, err
		}

		data, readErr := io.ReadAll(io.LimitReader(file, maxTaskWorkspaceUploadBytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if int64(len(data)) > maxTaskWorkspaceUploadBytes {
			return nil, fmt.Errorf("%w: %s", errTaskWorkspaceFileTooLarge, fileHeader.Filename)
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
			Key:         aws.String(storage.objectKey(taskWorkspaceStoragePrefix(deploymentID, projectID, taskKey) + relativePath)),
			Body:        bytes.NewReader(data),
			ContentType: aws.String(contentType),
		})
		if err != nil {
			return nil, err
		}

		results = append(results, UploadedTaskWorkspaceFile{
			Path:         "/task/" + relativePath,
			Name:         filepath.Base(relativePath),
			OriginalName: fileHeader.Filename,
			MimeType:     contentType,
			SizeBytes:    uint64(len(data)),
		})
	}

	return results, nil
}

func (s *Service) uploadBoardItemTaskWorkspaceFiles(
	deploymentID, actorID, projectID, itemID uint64,
	files []*multipart.FileHeader,
) ([]UploadedTaskWorkspaceFile, error) {
	if len(files) == 0 {
		return []UploadedTaskWorkspaceFile{}, nil
	}

	item, err := s.GetAuthorizedBoardItem(deploymentID, actorID, itemID, false)
	if err != nil {
		return nil, err
	}
	board, err := s.GetProjectBoardByID(deploymentID, actorID, item.BoardID)
	if err != nil {
		return nil, err
	}
	if board.ProjectID != projectID {
		return nil, gorm.ErrRecordNotFound
	}

	return uploadTaskWorkspaceFilesForTaskKey(deploymentID, board.ProjectID, item.TaskKey, files)
}

func (h *Handler) ListBoardItemTaskWorkspaceFiles(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}

	itemID, err := parseIDParam(c, "item_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid item_id")
	}

	deployment := handler.GetDeployment(c)
	listing, err := h.service.ListBoardItemTaskWorkspaceFiles(
		deployment.ID,
		actorID,
		projectID,
		itemID,
		c.Query("path"),
		parseBoolQuery(c.Query("include_archived")),
	)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return handler.SendNotFound(c, nil, "Board item not found")
		}
		return handler.SendInternalServerError(c, nil, "Failed to load task workspace")
	}

	return handler.SendSuccess(c, listing)
}

func (h *Handler) GetBoardItemTaskWorkspaceFileContent(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}

	itemID, err := parseIDParam(c, "item_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid item_id")
	}

	relativePath := c.Query("path")
	if strings.TrimSpace(relativePath) == "" {
		return handler.SendBadRequest(c, nil, "path query parameter is required")
	}

	deployment := handler.GetDeployment(c)
	content, err := h.service.GetBoardItemTaskWorkspaceFileContent(
		deployment.ID,
		actorID,
		projectID,
		itemID,
		relativePath,
		parseBoolQuery(c.Query("include_archived")),
	)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || isS3NotFound(err) {
			return handler.SendNotFound(c, nil, "Task workspace file not found")
		}
		if errors.Is(err, errTaskWorkspacePathRequired) ||
			errors.Is(err, errTaskWorkspacePathTraversalNotAllowed) ||
			errors.Is(err, errTaskWorkspaceFileTooLarge) {
			return handler.SendBadRequest(c, nil, "Invalid file path")
		}
		log.Printf("GetBoardItemTaskWorkspaceFileContent failed: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to load task workspace file")
	}

	return handler.SendSuccess(c, content)
}

func (h *Handler) DownloadBoardItemTaskWorkspaceFile(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}
	itemID, err := parseIDParam(c, "item_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid item_id")
	}
	relativePath := c.Query("path")
	if strings.TrimSpace(relativePath) == "" {
		return handler.SendBadRequest(c, nil, "path query parameter is required")
	}

	deployment := handler.GetDeployment(c)
	body, size, mimeType, err := h.service.StreamBoardItemTaskWorkspaceFile(
		deployment.ID,
		actorID,
		projectID,
		itemID,
		relativePath,
		parseBoolQuery(c.Query("include_archived")),
	)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || isS3NotFound(err) {
			return handler.SendNotFound(c, nil, "Task workspace file not found")
		}
		if errors.Is(err, errTaskWorkspacePathRequired) ||
			errors.Is(err, errTaskWorkspacePathTraversalNotAllowed) ||
			errors.Is(err, errTaskWorkspaceRequestedDirectory) ||
			errors.Is(err, errTaskWorkspacePathOutsideRoots) ||
			errors.Is(err, errTaskWorkspaceFileTooLarge) {
			return handler.SendBadRequest(c, nil, "Invalid file path")
		}
		log.Printf("DownloadBoardItemTaskWorkspaceFile storage read failed: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to load task workspace file")
	}
	defer body.Close()

	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set(fiber.HeaderContentType, mimeType)
	filename := filepath.Base(relativePath)
	if safeFilename, sanitizeErr := sanitizeUploadFilename(filename); sanitizeErr == nil && safeFilename != "" {
		c.Set(fiber.HeaderContentDisposition, fmt.Sprintf("attachment; filename=%q", safeFilename))
	} else {
		c.Set(fiber.HeaderContentDisposition, "attachment")
	}
	if size > 0 {
		return c.SendStream(body, int(size))
	}
	return c.SendStream(body)
}

func (h *Handler) ListThreadFilesystemEntries(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}

	threadID, err := parseIDParam(c, "thread_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid thread_id")
	}

	deployment := handler.GetDeployment(c)
	listing, err := h.service.ListThreadFilesystemEntries(
		deployment.ID,
		actorID,
		threadID,
		c.Query("path"),
	)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return handler.SendNotFound(c, nil, "Thread not found")
		}
		return handler.SendInternalServerError(c, nil, "Failed to load thread filesystem")
	}

	return handler.SendSuccess(c, listing)
}

func (h *Handler) GetThreadFilesystemFileContent(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}

	threadID, err := parseIDParam(c, "thread_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid thread_id")
	}

	relativePath := c.Query("path")
	if strings.TrimSpace(relativePath) == "" {
		return handler.SendBadRequest(c, nil, "path query parameter is required")
	}

	deployment := handler.GetDeployment(c)
	if _, err := h.service.GetThread(deployment.ID, actorID, threadID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return handler.SendNotFound(c, nil, "Thread not found")
		}
		log.Printf("GetThreadFilesystemFileContent GetThread failed: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to load thread filesystem file")
	}

	storage, err := resolveDeploymentAgentStorage(deployment.ID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to resolve deployment storage")
	}

	body, size, mimeType, err := getThreadFilesystemFileStreamFromStorage(
		storage,
		deployment.ID,
		threadID,
		relativePath,
	)
	if err != nil {
		if isS3NotFound(err) {
			return handler.SendNotFound(c, nil, "Thread filesystem file not found")
		}
		if errors.Is(err, errTaskWorkspacePathRequired) ||
			errors.Is(err, errTaskWorkspacePathTraversalNotAllowed) ||
			errors.Is(err, errTaskWorkspacePathOutsideRoots) ||
			errors.Is(err, errTaskWorkspaceRequestedDirectory) ||
			errors.Is(err, errTaskWorkspaceFileTooLarge) {
			return handler.SendBadRequest(c, nil, "Invalid file path")
		}
		log.Printf("GetThreadFilesystemFileContent storage read failed: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to load thread filesystem file")
	}
	defer body.Close()

	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set(fiber.HeaderContentType, mimeType)
	filename := filepath.Base(relativePath)
	if safeFilename, sanitizeErr := sanitizeUploadFilename(filename); sanitizeErr == nil && safeFilename != "" {
		c.Set(fiber.HeaderContentDisposition, fmt.Sprintf("attachment; filename=%q", safeFilename))
	} else {
		c.Set(fiber.HeaderContentDisposition, "attachment")
	}
	if size > 0 {
		return c.SendStream(body, int(size))
	}
	return c.SendStream(body)
}
