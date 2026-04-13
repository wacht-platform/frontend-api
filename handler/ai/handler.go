package ai

import (
	"encoding/base64"
	"errors"
	"mime/multipart"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
)

type Handler struct {
	service *Service
}

func NewHandler() *Handler { return &Handler{service: NewService()} }

func sessionHasActor(agentSession *model.AgentSession, actorID uint64) bool {
	return agentSession.ActorID == actorID
}

func (h *Handler) getActorScope(c fiber.Ctx) (uint64, *model.AgentSession, error) {
	session := handler.GetSession(c)
	if session == nil {
		return 0, nil, fiber.NewError(fiber.StatusUnauthorized, "Session required")
	}
	deployment := handler.GetDeployment(c)
	agentSession, err := h.service.GetActiveAgentSession(session.ID, deployment.ID)
	if err != nil {
		return 0, nil, fiber.NewError(fiber.StatusUnauthorized, "No active agent session")
	}
	return agentSession.ActorID, agentSession, nil
}

func parseIDParam(c fiber.Ctx, name string) (uint64, error) {
	return strconv.ParseUint(c.Params(name), 10, 64)
}

func parseStatusFilters(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	return result
}

func parseBoolQuery(raw string) bool {
	value := strings.TrimSpace(raw)
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}
	return parsed
}

func parseTimeIDCursor(raw string) (*time.Time, *uint64, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, nil, fiber.NewError(fiber.StatusBadRequest, "invalid cursor")
	}
	parts := strings.SplitN(string(decoded), "|", 2)
	if len(parts) != 2 {
		return nil, nil, fiber.NewError(fiber.StatusBadRequest, "invalid cursor")
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, nil, fiber.NewError(fiber.StatusBadRequest, "invalid cursor")
	}
	id, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return nil, nil, fiber.NewError(fiber.StatusBadRequest, "invalid cursor")
	}
	cursorTime := time.Unix(0, nanos).UTC()
	return &cursorTime, &id, nil
}

func requireMultipartFormRequest(c fiber.Ctx) error {
	contentType := strings.ToLower(strings.TrimSpace(c.Get("Content-Type")))
	if strings.HasPrefix(contentType, "multipart/form-data") {
		return nil
	}
	return handler.SendBadRequest(c, nil, "multipart/form-data is required")
}

func (h *Handler) ListActorProjects(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	deployment := handler.GetDeployment(c)
	projects, err := h.service.ListActorProjects(deployment.ID, actorID, parseBoolQuery(c.Query("include_archived")))
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, projects)
}

func (h *Handler) SearchActorProjects(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}

	limit := fiber.Query[int](c, "limit", 12)
	if limit <= 0 {
		limit = 12
	}
	if limit > 100 {
		limit = 100
	}

	cursorUpdatedAt, cursorID, err := parseTimeIDCursor(c.Query("cursor", ""))
	if err != nil {
		return err
	}

	deployment := handler.GetDeployment(c)
	projects, err := h.service.SearchActorProjects(
		deployment.ID,
		actorID,
		c.Query("q", ""),
		limit,
		cursorUpdatedAt,
		cursorID,
	)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, projects)
}

func (h *Handler) CreateActorProject(c fiber.Ctx) error {
	actorID, agentSession, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	req, vErr := handler.Validate[CreateActorProjectRequest](c)
	if vErr != nil {
		return handler.SendBadRequest(c, nil, "Invalid request body")
	}
	if req.AgentID == nil {
		return handler.SendBadRequest(c, nil, "agent_id is required")
	}
	if !sessionHasAgent(agentSession, *req.AgentID) {
		return handler.SendBadRequest(c, nil, "agent_id must be included in the session agent set")
	}
	selectedAgentID := *req.AgentID
	deployment := handler.GetDeployment(c)
	project, err := h.service.CreateActorProjectWithAgent(deployment.ID, actorID, selectedAgentID, *req)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, project)
}

func (h *Handler) CreateActorThread(c fiber.Ctx) error {
	actorID, agentSession, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	req, vErr := handler.Validate[CreateAgentThreadRequest](c)
	if vErr != nil {
		return handler.SendBadRequest(c, nil, "Invalid request body")
	}
	if req.AgentID == nil {
		return handler.SendBadRequest(c, nil, "agent_id is required")
	}
	if !sessionHasAgent(agentSession, *req.AgentID) {
		return handler.SendBadRequest(c, nil, "agent_id must be included in the session agent set")
	}
	selectedAgentID := *req.AgentID
	deployment := handler.GetDeployment(c)
	project, err := h.service.ResolveRecentActorProjectWithAgent(deployment.ID, actorID, selectedAgentID, true)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to resolve project for thread")
	}
	if project == nil {
		return handler.SendInternalServerError(c, nil, "Failed to resolve project for thread")
	}
	thread, err := h.service.CreateAgentThread(deployment.ID, actorID, project.ID, *req)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to create thread")
	}
	return handler.SendSuccess(c, thread)
}

func (h *Handler) GetActorProject(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}
	deployment := handler.GetDeployment(c)
	project, err := h.service.GetActorProject(deployment.ID, actorID, projectID)
	if err != nil {
		return handler.SendNotFound(c, nil, "Project not found")
	}
	return handler.SendSuccess(c, project)
}

func (h *Handler) UpdateActorProject(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}
	req, vErr := handler.Validate[UpdateActorProjectRequest](c)
	if vErr != nil {
		return handler.SendBadRequest(c, nil, "Invalid request body")
	}
	deployment := handler.GetDeployment(c)
	project, err := h.service.UpdateActorProject(deployment.ID, actorID, projectID, *req)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to update project")
	}
	return handler.SendSuccess(c, project)
}

func (h *Handler) ArchiveActorProject(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}
	deployment := handler.GetDeployment(c)
	project, err := h.service.SetActorProjectArchived(deployment.ID, actorID, projectID, true)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, project)
}

func (h *Handler) UnarchiveActorProject(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}
	deployment := handler.GetDeployment(c)
	project, err := h.service.SetActorProjectArchived(deployment.ID, actorID, projectID, false)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, project)
}

func (h *Handler) GetProjectBoard(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}
	deployment := handler.GetDeployment(c)
	if _, err := h.service.GetActorProject(deployment.ID, actorID, projectID); err != nil {
		return handler.SendNotFound(c, nil, "Project not found")
	}
	board, err := h.service.EnsureProjectBoard(deployment.ID, actorID, projectID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to resolve board")
	}
	return handler.SendSuccess(c, board)
}

func (h *Handler) ListProjectBoardItems(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}
	deployment := handler.GetDeployment(c)
	if _, err := h.service.GetActorProject(deployment.ID, actorID, projectID); err != nil {
		return handler.SendNotFound(c, nil, "Project not found")
	}
	board, err := h.service.GetProjectBoard(deployment.ID, actorID, projectID)
	if err != nil {
		return handler.SendSuccess(c, []model.ProjectTaskBoardItem{})
	}
	limit := fiber.Query[int](c, "limit", 60)
	if limit <= 0 {
		limit = 60
	}
	if limit > 200 {
		limit = 200
	}

	cursor := c.Query("cursor", "")
	var cursorCreatedAt *time.Time
	var cursorID *uint64
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		parts := strings.SplitN(string(decoded), "|", 2)
		if len(parts) != 2 {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		nanos, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		itemID, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		cursorTime := time.Unix(0, nanos).UTC()
		cursorCreatedAt = &cursorTime
		cursorID = &itemID
	}

	items, err := h.service.ListProjectBoardItems(
		board.ID,
		parseStatusFilters(c.Query("status")),
		parseBoolQuery(c.Query("include_archived")),
		parseBoolQuery(c.Query("archived_only")),
		limit,
		cursorCreatedAt,
		cursorID,
	)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, items)
}

func (h *Handler) CreateProjectBoardItem(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}
	if err := requireMultipartFormRequest(c); err != nil {
		return err
	}

	form, err := c.MultipartForm()
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid multipart form")
	}

	req := CreateProjectTaskBoardItemRequest{
		Title: c.FormValue("title"),
	}
	if value := strings.TrimSpace(c.FormValue("description")); value != "" {
		req.Description = &value
	}
	if value := strings.TrimSpace(c.FormValue("status")); value != "" {
		req.Status = &value
	}
	if value := strings.TrimSpace(c.FormValue("priority")); value != "" {
		req.Priority = &value
	}
	if value := strings.TrimSpace(c.FormValue("schedule_kind")); value != "" {
		req.ScheduleKind = &value
	}
	if value := strings.TrimSpace(c.FormValue("next_run_at")); value != "" {
		req.NextRunAt = &value
	}
	if value := strings.TrimSpace(c.FormValue("interval_seconds")); value != "" {
		parsed, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil {
			return handler.SendBadRequest(c, nil, "Invalid interval_seconds")
		}
		req.IntervalSeconds = &parsed
	}
	deployment := handler.GetDeployment(c)
	var files []*multipart.FileHeader
	if form != nil {
		files = form.File["files"]
	}
	item, err := h.service.CreateProjectBoardItem(deployment.ID, actorID, projectID, req, files)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to create project task board item")
	}
	return handler.SendSuccess(c, item)
}

func (h *Handler) GetBoardItem(c fiber.Ctx) error {
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
	item, err := h.service.GetProjectBoardItem(
		deployment.ID,
		actorID,
		projectID,
		itemID,
		parseBoolQuery(c.Query("include_archived")),
	)
	if err != nil {
		return handler.SendNotFound(c, nil, "Board item not found")
	}
	return handler.SendSuccess(c, item)
}

func (h *Handler) ListBoardItemEvents(c fiber.Ctx) error {
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
	if _, err := h.service.GetProjectBoardItem(deployment.ID, actorID, projectID, itemID, parseBoolQuery(c.Query("include_archived"))); err != nil {
		return handler.SendNotFound(c, nil, "Board item not found")
	}

	limit := fiber.Query[int](c, "limit", 40)
	if limit <= 0 {
		limit = 40
	}
	if limit > 200 {
		limit = 200
	}

	cursorCreatedAt, cursorID, err := parseTimeIDCursor(c.Query("cursor", ""))
	if err != nil {
		return err
	}

	events, err := h.service.ListBoardItemEvents(itemID, limit, cursorCreatedAt, cursorID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, events)
}

func (h *Handler) ListBoardItemAssignments(c fiber.Ctx) error {
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
	if _, err := h.service.GetProjectBoardItem(deployment.ID, actorID, projectID, itemID, parseBoolQuery(c.Query("include_archived"))); err != nil {
		return handler.SendNotFound(c, nil, "Board item not found")
	}

	limit := fiber.Query[int](c, "limit", 40)
	if limit <= 0 {
		limit = 40
	}
	if limit > 200 {
		limit = 200
	}

	cursor := c.Query("cursor", "")
	var cursorAssignmentOrder *int
	var cursorID *uint64
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		parts := strings.SplitN(string(decoded), "|", 2)
		if len(parts) != 2 {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		assignmentOrder, err := strconv.Atoi(parts[0])
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		assignmentID, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		cursorAssignmentOrder = &assignmentOrder
		cursorID = &assignmentID
	}

	assignments, err := h.service.ListBoardItemAssignments(itemID, limit, cursorAssignmentOrder, cursorID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, assignments)
}

func (h *Handler) UpdateBoardItem(c fiber.Ctx) error {
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
	if err := requireMultipartFormRequest(c); err != nil {
		return err
	}

	form, err := c.MultipartForm()
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid multipart form")
	}

	req := UpdateProjectTaskBoardItemRequest{}
	if value := strings.TrimSpace(c.FormValue("title")); value != "" {
		req.Title = &value
	}
	if description, ok := func() (*string, bool) {
		if form == nil {
			return nil, false
		}
		if _, exists := form.Value["description"]; !exists {
			return nil, false
		}
		value := strings.TrimSpace(c.FormValue("description"))
		return &value, true
	}(); ok {
		req.Description = description
	}
	if value := strings.TrimSpace(c.FormValue("status")); value != "" {
		req.Status = &value
	}
	if value := strings.TrimSpace(c.FormValue("priority")); value != "" {
		req.Priority = &value
	}
	if value := strings.TrimSpace(c.FormValue("schedule_kind")); value != "" {
		req.ScheduleKind = &value
	}
	if value := strings.TrimSpace(c.FormValue("next_run_at")); value != "" {
		req.NextRunAt = &value
	}
	if value := strings.TrimSpace(c.FormValue("interval_seconds")); value != "" {
		parsed, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil {
			return handler.SendBadRequest(c, nil, "Invalid interval_seconds")
		}
		req.IntervalSeconds = &parsed
	}
	if value := strings.TrimSpace(c.FormValue("clear_schedule")); value != "" {
		parsed, parseErr := strconv.ParseBool(value)
		if parseErr != nil {
			return handler.SendBadRequest(c, nil, "Invalid clear_schedule")
		}
		req.ClearSchedule = &parsed
	}
	deployment := handler.GetDeployment(c)
	var files []*multipart.FileHeader
	if form != nil {
		files = form.File["files"]
	}
	item, err := h.service.UpdateProjectBoardItem(deployment.ID, actorID, projectID, itemID, req, files)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to update project task board item")
	}
	return handler.SendSuccess(c, item)
}

func (h *Handler) ArchiveBoardItem(c fiber.Ctx) error {
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
	item, err := h.service.ArchiveProjectBoardItem(deployment.ID, actorID, projectID, itemID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to archive task")
	}
	return handler.SendSuccess(c, item)
}

func (h *Handler) UnarchiveBoardItem(c fiber.Ctx) error {
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
	item, err := h.service.UnarchiveProjectBoardItem(deployment.ID, actorID, projectID, itemID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to unarchive task")
	}
	return handler.SendSuccess(c, item)
}

func (h *Handler) AppendBoardItemJournal(c fiber.Ctx) error {
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
	if err := requireMultipartFormRequest(c); err != nil {
		return err
	}

	form, err := c.MultipartForm()
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid multipart form")
	}

	summary := strings.TrimSpace(c.FormValue("summary"))
	if summary == "" {
		return handler.SendBadRequest(c, nil, "summary must not be empty")
	}

	var bodyMarkdown *string
	if value := strings.TrimSpace(c.FormValue("body_markdown")); value != "" {
		bodyMarkdown = &value
	}

	var details *string
	if value := strings.TrimSpace(c.FormValue("details")); value != "" {
		details = &value
	}

	var files []*multipart.FileHeader
	if form != nil {
		files = form.File["files"]
	}

	var attachments []UploadedTaskWorkspaceFile
	if len(files) > 0 {
		deployment := handler.GetDeployment(c)
		attachments, err = h.service.uploadBoardItemTaskWorkspaceFiles(deployment.ID, actorID, projectID, itemID, files)
		if err != nil {
			return handler.SendInternalServerError(c, nil, "Failed to upload task files")
		}
	}

	deployment := handler.GetDeployment(c)
	event, err := h.service.AppendBoardItemJournalEntry(
		deployment.ID,
		actorID,
		projectID,
		itemID,
		summary,
		details,
		bodyMarkdown,
		attachments,
	)
	if err != nil {
		if strings.Contains(err.Error(), "summary must not be empty") {
			return handler.SendBadRequest(c, nil, err.Error())
		}
		return handler.SendInternalServerError(c, nil, "Failed to append journal entry")
	}

	return handler.SendSuccess(c, event)
}

func (h *Handler) ListProjectThreads(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}
	deployment := handler.GetDeployment(c)
	if _, err := h.service.GetActorProject(deployment.ID, actorID, projectID); err != nil {
		return handler.SendNotFound(c, nil, "Project not found")
	}

	limit := fiber.Query[int](c, "limit", 10)
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	cursorLastActivityAt, cursorID, err := parseTimeIDCursor(c.Query("cursor", ""))
	if err != nil {
		return err
	}

	threads, err := h.service.SearchProjectThreads(
		deployment.ID,
		actorID,
		projectID,
		c.Query("q", ""),
		parseBoolQuery(c.Query("include_archived")),
		parseBoolQuery(c.Query("archived_only")),
		limit,
		cursorLastActivityAt,
		cursorID,
	)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, threads)
}

func (h *Handler) SearchActorThreads(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}

	limit := fiber.Query[int](c, "limit", 16)
	if limit <= 0 {
		limit = 16
	}
	if limit > 100 {
		limit = 100
	}

	cursorLastActivityAt, cursorID, err := parseTimeIDCursor(c.Query("cursor", ""))
	if err != nil {
		return err
	}

	deployment := handler.GetDeployment(c)
	threads, err := h.service.SearchActorThreads(
		deployment.ID,
		actorID,
		c.Query("q", ""),
		limit,
		cursorLastActivityAt,
		cursorID,
	)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, threads)
}

func (h *Handler) CreateProjectThread(c fiber.Ctx) error {
	actorID, agentSession, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	projectID, err := parseIDParam(c, "project_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid project_id")
	}
	req, vErr := handler.Validate[CreateAgentThreadRequest](c)
	if vErr != nil {
		return handler.SendBadRequest(c, nil, "Invalid request body")
	}
	if req.AgentID == nil {
		return handler.SendBadRequest(c, nil, "agent_id is required")
	}
	if !sessionHasAgent(agentSession, *req.AgentID) {
		return handler.SendBadRequest(c, nil, "agent_id must be included in the session agent set")
	}
	deployment := handler.GetDeployment(c)
	thread, err := h.service.CreateAgentThread(deployment.ID, actorID, projectID, *req)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, thread)
}

func (h *Handler) UpdateThread(c fiber.Ctx) error {
	actorID, agentSession, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	threadID, err := parseIDParam(c, "thread_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid thread_id")
	}
	req, vErr := handler.Validate[UpdateAgentThreadRequest](c)
	if vErr != nil {
		return handler.SendBadRequest(c, nil, "Invalid request body")
	}
	if req.AgentID != nil && !sessionHasAgent(agentSession, *req.AgentID) {
		return handler.SendBadRequest(c, nil, "agent_id must be included in the session agent set")
	}
	deployment := handler.GetDeployment(c)
	thread, err := h.service.UpdateAgentThread(deployment.ID, actorID, threadID, *req)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, thread)
}

func (h *Handler) ArchiveThread(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	threadID, err := parseIDParam(c, "thread_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid thread_id")
	}
	deployment := handler.GetDeployment(c)
	thread, err := h.service.SetAgentThreadArchived(deployment.ID, actorID, threadID, true)
	if err != nil {
		if errors.Is(err, ErrInternalThreadArchiveNotAllowed) {
			return handler.SendBadRequest(c, nil, "Review and execution threads cannot be archived")
		}
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, thread)
}

func (h *Handler) UnarchiveThread(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	threadID, err := parseIDParam(c, "thread_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid thread_id")
	}
	deployment := handler.GetDeployment(c)
	thread, err := h.service.SetAgentThreadArchived(deployment.ID, actorID, threadID, false)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, thread)
}

func (h *Handler) GetThread(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	threadID, err := parseIDParam(c, "thread_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid thread_id")
	}
	deployment := handler.GetDeployment(c)
	thread, err := h.service.GetThread(deployment.ID, actorID, threadID)
	if err != nil {
		return handler.SendNotFound(c, nil, "Thread not found")
	}
	return handler.SendSuccess(c, thread)
}

func (h *Handler) ListThreadEvents(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	threadID, err := parseIDParam(c, "thread_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid thread_id")
	}
	deployment := handler.GetDeployment(c)
	if _, err := h.service.GetThread(deployment.ID, actorID, threadID); err != nil {
		return handler.SendForbidden(c, nil, "Forbidden")
	}

	limit := fiber.Query[int](c, "limit", 40)
	if limit <= 0 {
		limit = 40
	}
	if limit > 200 {
		limit = 200
	}

	cursor := c.Query("cursor", "")
	var cursorCreatedAt *time.Time
	var cursorID *uint64
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		parts := strings.SplitN(string(decoded), "|", 2)
		if len(parts) != 2 {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		nanos, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		eventID, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		cursorTime := time.Unix(0, nanos).UTC()
		cursorCreatedAt = &cursorTime
		cursorID = &eventID
	}

	events, err := h.service.ListThreadEvents(threadID, limit, cursorCreatedAt, cursorID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, events)
}

func (h *Handler) ListThreadAssignments(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	threadID, err := parseIDParam(c, "thread_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid thread_id")
	}
	deployment := handler.GetDeployment(c)
	if _, err := h.service.GetThread(deployment.ID, actorID, threadID); err != nil {
		return handler.SendForbidden(c, nil, "Forbidden")
	}

	limit := fiber.Query[int](c, "limit", 40)
	if limit <= 0 {
		limit = 40
	}
	if limit > 200 {
		limit = 200
	}

	cursor := c.Query("cursor", "")
	var cursorAssignmentOrder *int
	var cursorID *uint64
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		parts := strings.SplitN(string(decoded), "|", 2)
		if len(parts) != 2 {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		assignmentOrder, err := strconv.Atoi(parts[0])
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		assignmentID, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		cursorAssignmentOrder = &assignmentOrder
		cursorID = &assignmentID
	}

	assignments, err := h.service.ListThreadAssignments(threadID, limit, cursorAssignmentOrder, cursorID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, assignments)
}

func (h *Handler) ListThreadTaskGraphs(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	threadID, err := parseIDParam(c, "thread_id")
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid thread_id")
	}
	deployment := handler.GetDeployment(c)
	if _, err := h.service.GetThread(deployment.ID, actorID, threadID); err != nil {
		return handler.SendForbidden(c, nil, "Forbidden")
	}

	limit := fiber.Query[int](c, "limit", 10)
	if limit < 1 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	cursor := c.Query("cursor", "")
	var cursorVersion *int
	var cursorID *uint64
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		parts := strings.SplitN(string(decoded), "|", 2)
		if len(parts) != 2 {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		version, err := strconv.Atoi(parts[0])
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		graphID, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		cursorVersion = &version
		cursorID = &graphID
	}

	graphs, err := h.service.ListTaskGraphBundles(deployment.ID, threadID, limit, cursorVersion, cursorID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Internal server error")
	}
	return handler.SendSuccess(c, graphs)
}
