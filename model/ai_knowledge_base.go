package model

import (
	"gorm.io/datatypes"
)

type AIKnowledgeBase struct {
	Model
	Name           string            `json:"name"           gorm:"not null"`
	Description    *string           `json:"description"`
	DeploymentID   uint64            `json:"deployment_id"  gorm:"not null;index"`
	Deployment     Deployment        `json:"-"              gorm:"foreignKey:DeploymentID"`
	Configuration  datatypes.JSONMap `json:"configuration"  gorm:"not null;default:'{}'"`

	Documents []AIKnowledgeBaseDocument `json:"documents,omitempty" gorm:"foreignKey:KnowledgeBaseID;constraint:OnDelete:CASCADE;"`
	Agents    []AIAgent                 `json:"agents,omitempty"    gorm:"many2many:ai_agent_knowledge_bases;"`
}

type AIKnowledgeBaseDocument struct {
	Model
	Title               string            `json:"title"                gorm:"not null"`
	Description         *string           `json:"description"`
	FileName            string            `json:"file_name"            gorm:"not null"`
	FileSize            uint64            `json:"file_size"            gorm:"not null"`
	FileType            string            `json:"file_type"            gorm:"not null"`
	FileURL             string            `json:"file_url"             gorm:"not null"`
	KnowledgeBaseID     uint64            `json:"knowledge_base_id"    gorm:"not null;index"`
	KnowledgeBase       AIKnowledgeBase   `json:"knowledge_base"       gorm:"foreignKey:KnowledgeBaseID;constraint:OnDelete:CASCADE"`
	ProcessingMetadata  datatypes.JSONMap `json:"processing_metadata"`
	UsageCount          uint64            `json:"usage_count"          gorm:"not null;default:0"`
}

type AIKnowledgeBaseConfiguration struct {
	ChunkSize        *int     `json:"chunk_size,omitempty"`        // Size of text chunks for processing
	ChunkOverlap     *int     `json:"chunk_overlap,omitempty"`     // Overlap between chunks
	EmbeddingModel   string   `json:"embedding_model"`             // Model used for embeddings

	DefaultMaxResults          *uint32  `json:"default_max_results,omitempty"`
	DefaultSimilarityThreshold *float32 `json:"default_similarity_threshold,omitempty"`
	EnableSemanticSearch       bool     `json:"enable_semantic_search"`
	EnableKeywordSearch        bool     `json:"enable_keyword_search"`

	SupportedFileTypes []string `json:"supported_file_types"`
	MaxFileSize        *uint64  `json:"max_file_size,omitempty"`
	AutoProcessing     bool     `json:"auto_processing"`

	ExtractMetadata    bool     `json:"extract_metadata"`
	CustomMetadataKeys []string `json:"custom_metadata_keys,omitempty"`
}

type DocumentProcessingStatus string

const (
	DocumentProcessingStatusPending    DocumentProcessingStatus = "pending"
	DocumentProcessingStatusProcessing DocumentProcessingStatus = "processing"
	DocumentProcessingStatusCompleted  DocumentProcessingStatus = "completed"
	DocumentProcessingStatusFailed     DocumentProcessingStatus = "failed"
)

type DocumentProcessingMetadata struct {
	Status           DocumentProcessingStatus `json:"status"`
	ProcessedAt      *string                  `json:"processed_at,omitempty"`
	ChunkCount       *int                     `json:"chunk_count,omitempty"`
	ErrorMessage     *string                  `json:"error_message,omitempty"`
	ProcessingTimeMs *int64                   `json:"processing_time_ms,omitempty"`
	ExtractedText    *string                  `json:"extracted_text,omitempty"`
	Metadata         map[string]interface{}   `json:"metadata,omitempty"`
}

func NewDefaultKnowledgeBaseConfiguration() *AIKnowledgeBaseConfiguration {
	chunkSize := 1000
	chunkOverlap := 200
	maxResults := uint32(10)
	threshold := float32(0.7)
	maxFileSize := uint64(50 * 1024 * 1024) 

	return &AIKnowledgeBaseConfiguration{
		ChunkSize:                  &chunkSize,
		ChunkOverlap:               &chunkOverlap,
		EmbeddingModel:             "text-embedding-ada-002",
		DefaultMaxResults:          &maxResults,
		DefaultSimilarityThreshold: &threshold,
		EnableSemanticSearch:       true,
		EnableKeywordSearch:        true,
		SupportedFileTypes: []string{
			"pdf", "txt", "md", "docx", "html", "csv", "json",
		},
		MaxFileSize:        &maxFileSize,
		AutoProcessing:     true,
		ExtractMetadata:    true,
		CustomMetadataKeys: []string{},
	}
}

// NewDocumentProcessingMetadata creates a new document processing metadata with pending status
func NewDocumentProcessingMetadata() *DocumentProcessingMetadata {
	return &DocumentProcessingMetadata{
		Status:   DocumentProcessingStatusPending,
		Metadata: make(map[string]interface{}),
	}
}

// MarkProcessingStarted marks the document as processing
func (dpm *DocumentProcessingMetadata) MarkProcessingStarted() {
	dpm.Status = DocumentProcessingStatusProcessing
}

// MarkProcessingCompleted marks the document as completed with chunk count
func (dpm *DocumentProcessingMetadata) MarkProcessingCompleted(chunkCount int, processingTimeMs int64) {
	dpm.Status = DocumentProcessingStatusCompleted
	dpm.ChunkCount = &chunkCount
	dpm.ProcessingTimeMs = &processingTimeMs
}

// MarkProcessingFailed marks the document as failed with error message
func (dpm *DocumentProcessingMetadata) MarkProcessingFailed(errorMessage string) {
	dpm.Status = DocumentProcessingStatusFailed
	dpm.ErrorMessage = &errorMessage
}

// IsProcessed returns true if the document has been successfully processed
func (dpm *DocumentProcessingMetadata) IsProcessed() bool {
	return dpm.Status == DocumentProcessingStatusCompleted
}

// IsFailed returns true if the document processing failed
func (dpm *DocumentProcessingMetadata) IsFailed() bool {
	return dpm.Status == DocumentProcessingStatusFailed
}

// IsProcessing returns true if the document is currently being processed
func (dpm *DocumentProcessingMetadata) IsProcessing() bool {
	return dpm.Status == DocumentProcessingStatusProcessing
}

// IncrementUsage increments the usage count for a document
func (doc *AIKnowledgeBaseDocument) IncrementUsage() {
	doc.UsageCount++
}

// GetFileExtension returns the file extension from the file name
func (doc *AIKnowledgeBaseDocument) GetFileExtension() string {
	if len(doc.FileName) == 0 {
		return ""
	}

	for i := len(doc.FileName) - 1; i >= 0; i-- {
		if doc.FileName[i] == '.' {
			return doc.FileName[i+1:]
		}
	}
	return ""
}

func (doc *AIKnowledgeBaseDocument) IsSupported(supportedTypes []string) bool {
	ext := doc.GetFileExtension()
	for _, supportedType := range supportedTypes {
		if ext == supportedType {
			return true
		}
	}
	return false
}
