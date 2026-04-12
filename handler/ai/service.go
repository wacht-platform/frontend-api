package ai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
	"github.com/wacht-platform/frontend-api/service"
	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

type allowlistedAgentRow struct {
	ID          uint64          `gorm:"column:id"`
	Name        string          `gorm:"column:name"`
	Description string          `gorm:"column:description"`
	ChildAgents json.RawMessage `gorm:"column:child_agents"`
}

type hydratedSessionRow struct {
	SessionID uint64          `gorm:"column:session_id"`
	Actor     json.RawMessage `gorm:"column:actor"`
	Agents    json.RawMessage `gorm:"column:agents"`
}

var ErrInternalThreadArchiveNotAllowed = errors.New("review and execution threads cannot be archived")

const (
	defaultActorProjectName   = "Default"
	activeProjectStatus       = "active"
	threadPurposeConversation = "conversation"
	threadPurposeCoordinator  = "coordinator"
	threadPurposeExecution    = "execution"
	threadPurposeReview       = "review"
	taskPriorityUrgent        = "urgent"
	taskPriorityHigh          = "high"
	taskPriorityNeutral       = "neutral"
	taskPriorityLow           = "low"
	taskScheduleKindOnce      = "once"
	taskScheduleKindInterval  = "interval"
)

type defaultProjectThreadSpec struct {
	Title              string
	ThreadPurpose      string
	AcceptsAssignments bool
	Responsibility     *string
}

var defaultProjectThreadSpecs = []defaultProjectThreadSpec{
	{
		Title:              "Coordinator",
		ThreadPurpose:      threadPurposeCoordinator,
		AcceptsAssignments: false,
		Responsibility:     stringPtr("Project coordinator"),
	},
	{
		Title:              "Review",
		ThreadPurpose:      threadPurposeReview,
		AcceptsAssignments: true,
		Responsibility:     stringPtr("Project reviewer"),
	},
}

func NewService() *Service {
	return &Service{db: database.Connection}
}

func stringPtr(value string) *string {
	return &value
}

func parseTaskScheduleRequest(
	scheduleKind *string,
	nextRunAt *string,
	intervalSeconds *int64,
) (*model.ProjectTaskSchedule, error) {
	if scheduleKind == nil && nextRunAt == nil && intervalSeconds == nil {
		return nil, nil
	}
	if scheduleKind == nil || nextRunAt == nil {
		return nil, fmt.Errorf("schedule_kind and next_run_at are required together")
	}
	kind := strings.TrimSpace(*scheduleKind)
	parsedNextRunAt, err := time.Parse(time.RFC3339, strings.TrimSpace(*nextRunAt))
	if err != nil {
		return nil, fmt.Errorf("invalid next_run_at: %w", err)
	}
	switch kind {
	case taskScheduleKindOnce:
		if intervalSeconds != nil {
			return nil, fmt.Errorf("once schedules must not set interval_seconds")
		}
	case taskScheduleKindInterval:
		if intervalSeconds == nil || *intervalSeconds <= 0 {
			return nil, fmt.Errorf("interval schedules require interval_seconds > 0")
		}
	default:
		return nil, fmt.Errorf("unsupported schedule_kind")
	}
	return &model.ProjectTaskSchedule{
		Status:          "active",
		ScheduleKind:    kind,
		IntervalSeconds: intervalSeconds,
		NextRunAt:       parsedNextRunAt,
	}, nil
}

func (s *Service) getProjectTaskSchedule(tx *gorm.DB, templateBoardItemID uint64) (*model.ProjectTaskSchedule, error) {
	var schedule model.ProjectTaskSchedule
	err := tx.Where("template_board_item_id = ?", templateBoardItemID).First(&schedule).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &schedule, nil
}

func (s *Service) attachProjectTaskSchedule(tx *gorm.DB, item *model.ProjectTaskBoardItem) error {
	if item == nil {
		return nil
	}
	schedule, err := s.getProjectTaskSchedule(tx, item.ID)
	if err != nil {
		return err
	}
	item.Schedule = schedule
	return nil
}

func (s *Service) attachProjectTaskSchedules(tx *gorm.DB, items []model.ProjectTaskBoardItem) error {
	if len(items) == 0 {
		return nil
	}

	ids := make([]uint64, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}

	var schedules []model.ProjectTaskSchedule
	if err := tx.Where("template_board_item_id IN ?", ids).Find(&schedules).Error; err != nil {
		return err
	}

	scheduleByTemplateID := make(map[uint64]*model.ProjectTaskSchedule, len(schedules))
	for index := range schedules {
		schedule := &schedules[index]
		scheduleByTemplateID[schedule.TemplateBoardItemID] = schedule
	}

	for index := range items {
		items[index].Schedule = scheduleByTemplateID[items[index].ID]
	}

	return nil
}

func (s *Service) reconcileProjectTaskSchedule(
	tx *gorm.DB,
	templateBoardItemID uint64,
	schedule *model.ProjectTaskSchedule,
	clear bool,
) error {
	if clear {
		return tx.Where("template_board_item_id = ?", templateBoardItemID).
			Delete(&model.ProjectTaskSchedule{}).Error
	}
	if schedule == nil {
		return nil
	}

	existing, err := s.getProjectTaskSchedule(tx, templateBoardItemID)
	if err != nil {
		return err
	}

	schedule.TemplateBoardItemID = templateBoardItemID
	if existing == nil {
		schedule.ID = idgen.NextID()
		return tx.Create(schedule).Error
	}

	return tx.Model(&model.ProjectTaskSchedule{}).
		Where("id = ?", existing.ID).
		Updates(map[string]any{
			"status":           "active",
			"schedule_kind":    schedule.ScheduleKind,
			"interval_seconds": schedule.IntervalSeconds,
			"next_run_at":      schedule.NextRunAt,
		}).Error
}

func optionalUint64(value uint64) *uint64 {
	if value == 0 {
		return nil
	}
	return &value
}

func normalizeOptionalTrimmedString(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func isAllowedThreadPurpose(value string) bool {
	switch value {
	case threadPurposeConversation, threadPurposeCoordinator, threadPurposeExecution, threadPurposeReview:
		return true
	default:
		return false
	}
}

func (s *Service) GetActiveAgentSession(sessionID, deploymentID uint64) (*model.AgentSession, error) {
	var agentSession model.AgentSession
	err := s.db.Where(
		"session_id = ? AND deployment_id = ? AND (expires_at IS NULL OR expires_at > ?)",
		sessionID, deploymentID, time.Now(),
	).First(&agentSession).Error
	if err != nil {
		return nil, err
	}
	return &agentSession, nil
}

func (s *Service) GetHydratedAgentSessionResponse(sessionID, deploymentID uint64) (*AgentSessionResponse, error) {
	var row hydratedSessionRow
	if err := s.db.Raw(`
		SELECT
			s.id AS session_id,
			json_build_object(
				'id', a.id::text,
				'display_name', a.display_name,
				'subject_type', a.subject_type,
				'external_key', a.external_key
			) AS actor,
			COALESCE((
				SELECT json_agg(
					json_build_object(
						'id', root.id::text,
						'name', root.name,
						'description', root.description,
						'child_agents', COALESCE(children.child_agents, '[]'::json)
					)
					ORDER BY root.name ASC
				)
				FROM ai_agents root
				LEFT JOIN LATERAL (
					SELECT json_agg(
						json_build_object(
							'id', child.id::text,
							'name', child.name,
							'description', child.description
						)
						ORDER BY child.name ASC
					) AS child_agents
					FROM ai_agents child
					WHERE child.deployment_id = s.deployment_id
						AND child.id IN (
							SELECT value::bigint
							FROM jsonb_array_elements_text(COALESCE(root.sub_agents, '[]'::jsonb))
						)
				) children ON TRUE
				WHERE root.deployment_id = s.deployment_id
					AND root.id = ANY(s.agent_ids)
			), '[]'::json) AS agents
		FROM agent_sessions s
		JOIN actors a
			ON a.id = s.actor_id
			AND a.deployment_id = s.deployment_id
		WHERE s.session_id = ?
			AND s.deployment_id = ?
			AND (s.expires_at IS NULL OR s.expires_at > ?)
		LIMIT 1
	`, sessionID, deploymentID, time.Now()).Scan(&row).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch hydrated agent session: %w", err)
	}
	if row.SessionID == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	response := &AgentSessionResponse{
		SessionID: row.SessionID,
	}
	if len(row.Actor) > 0 && string(row.Actor) != "null" {
		if err := json.Unmarshal(row.Actor, &response.Actor); err != nil {
			return nil, fmt.Errorf("failed to parse session actor: %w", err)
		}
	}
	if len(row.Agents) > 0 && string(row.Agents) != "null" {
		if err := json.Unmarshal(row.Agents, &response.Agents); err != nil {
			return nil, fmt.Errorf("failed to parse session agents: %w", err)
		}
	}

	return response, nil
}

func (s *Service) GetActorByID(deploymentID, actorID uint64) (*model.Actor, error) {
	var actor model.Actor
	if err := s.db.Where("id = ? AND deployment_id = ?", actorID, deploymentID).First(&actor).Error; err != nil {
		return nil, err
	}
	return &actor, nil
}

func (s *Service) ListActorsForSession(deploymentID, actorID uint64) ([]model.Actor, error) {
	var actors []model.Actor
	if err := s.db.Where("deployment_id = ? AND id = ?", deploymentID, actorID).Find(&actors).Error; err != nil {
		return nil, err
	}
	return actors, nil
}

func (s *Service) GetAllowlistedActors(deploymentID, actorID uint64) ([]ActorSummary, error) {
	var actors []model.Actor
	if err := s.db.Where("deployment_id = ? AND id = ?", deploymentID, actorID).
		Order("updated_at DESC").
		Find(&actors).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch actors: %w", err)
	}

	result := make([]ActorSummary, 0, len(actors))
	for _, actor := range actors {
		result = append(result, ActorSummary{
			ID:          actor.ID,
			DisplayName: actor.DisplayName,
			SubjectType: actor.SubjectType,
			ExternalKey: actor.ExternalKey,
		})
	}

	return result, nil
}

func (s *Service) GetAllowlistedAgents(deploymentID uint64, agentIDs []int64) ([]Agent, error) {
	var rows []allowlistedAgentRow
	if err := s.db.Raw(`
		WITH selected_agents AS (
			SELECT a.id, a.name, a.description, COALESCE(a.sub_agents, '[]'::jsonb) AS sub_agents
			FROM ai_agents a
			WHERE a.deployment_id = ? AND a.id = ANY(?)
		)
		SELECT
			a.id,
			a.name,
			a.description,
			COALESCE(children.child_agents, '[]'::json) AS child_agents
		FROM selected_agents a
		LEFT JOIN LATERAL (
			SELECT json_agg(
				json_build_object(
					'id', c.id::text,
					'name', c.name,
					'description', COALESCE(c.description, '')
				)
				ORDER BY c.name ASC
			) AS child_agents
			FROM ai_agents c
			WHERE c.deployment_id = ?
				AND c.id IN (
					SELECT value::bigint
					FROM jsonb_array_elements_text(a.sub_agents)
				)
		) children ON TRUE
		ORDER BY a.name ASC
	`, deploymentID, pq.Array(agentIDs), deploymentID).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch agents: %w", err)
	}

	result := make([]Agent, 0, len(rows))
	for _, row := range rows {
		agent := Agent{
			ID:          row.ID,
			Name:        row.Name,
			Description: row.Description,
		}

		if len(row.ChildAgents) > 0 && string(row.ChildAgents) != "null" {
			var children []Agent
			if err := json.Unmarshal(row.ChildAgents, &children); err != nil {
				return nil, fmt.Errorf("failed to parse child agents for agent %d: %w", row.ID, err)
			}
			if len(children) > 0 {
				agent.ChildAgents = children
			}
		}

		result = append(result, agent)
	}

	return result, nil
}

func (s *Service) CreateActorProject(deploymentID, actorID uint64, req CreateActorProjectRequest) (*model.ActorProject, error) {
	return s.CreateActorProjectWithAgent(deploymentID, actorID, 0, req)
}

func (s *Service) CreateActorProjectWithAgent(deploymentID, actorID, selectedAgentID uint64, req CreateActorProjectRequest) (*model.ActorProject, error) {
	if selectedAgentID == 0 {
		return nil, fmt.Errorf("selected agent is required to create project default threads")
	}
	status := "active"
	if req.Status != nil && strings.TrimSpace(*req.Status) != "" {
		status = strings.TrimSpace(*req.Status)
	}
	description := normalizeOptionalTrimmedString(req.Description)
	project := model.ActorProject{
		Model:        model.Model{ID: idgen.NextID()},
		DeploymentID: deploymentID,
		ActorID:      actorID,
		Name:         strings.TrimSpace(req.Name),
		Description:  description,
		Status:       status,
		Metadata:     json.RawMessage("{}"),
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&project).Error; err != nil {
			return err
		}
		return s.ensureProjectDefaultThreads(tx, &project, optionalUint64(selectedAgentID))
	}); err != nil {
		return nil, err
	}
	return &project, nil
}

func (s *Service) EnsureDefaultActorProject(deploymentID, actorID uint64) (*model.ActorProject, error) {
	return s.EnsureDefaultActorProjectWithAgent(deploymentID, actorID, 0)
}

func (s *Service) EnsureDefaultActorProjectWithAgent(deploymentID, actorID, selectedAgentID uint64) (*model.ActorProject, error) {
	var project model.ActorProject
	err := s.db.
		Where(
			"deployment_id = ? AND actor_id = ? AND name = ? AND archived_at IS NULL",
			deploymentID,
			actorID,
			defaultActorProjectName,
		).
		Order("updated_at DESC").
		First(&project).Error
	if err == nil {
		if ensureErr := s.ensureProjectDefaultThreads(s.db, &project, nil); ensureErr != nil {
			return nil, ensureErr
		}
		return &project, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to load default actor project: %w", err)
	}
	if selectedAgentID == 0 {
		return nil, fmt.Errorf("selected agent is required to create default project threads")
	}

	project = model.ActorProject{
		Model:        model.Model{ID: idgen.NextID()},
		DeploymentID: deploymentID,
		ActorID:      actorID,
		Name:         defaultActorProjectName,
		Status:       activeProjectStatus,
		Metadata:     json.RawMessage("{}"),
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&project).Error; err != nil {
			return err
		}
		return s.ensureProjectDefaultThreads(tx, &project, optionalUint64(selectedAgentID))
	}); err != nil {
		return nil, fmt.Errorf("failed to create default actor project: %w", err)
	}

	return &project, nil
}

func (s *Service) ensureProjectDefaultThreads(
	db *gorm.DB,
	project *model.ActorProject,
	selectedAgentID *uint64,
) error {
	now := time.Now()
	defaultThreadIDs := map[string]uint64{}
	deploymentID := project.DeploymentID
	actorID := project.ActorID
	projectID := project.ID

	for _, spec := range defaultProjectThreadSpecs {
		var existing model.AgentThread
		err := db.
			Where(
				"deployment_id = ? AND actor_id = ? AND project_id = ? AND thread_purpose = ? AND archived_at IS NULL",
				deploymentID,
				actorID,
				projectID,
				spec.ThreadPurpose,
			).
			Order("updated_at DESC").
			First(&existing).Error
		if err == nil {
			if existing.SystemInstructions == nil || strings.TrimSpace(*existing.SystemInstructions) == "" {
				generated, renderErr := buildProjectThreadSystemInstructions(project.Name, project.Description, spec.ThreadPurpose)
				if renderErr != nil {
					return renderErr
				}
				updates := map[string]any{
					"system_instructions": generated,
				}
				if existing.Responsibility == nil || strings.TrimSpace(*existing.Responsibility) == "" {
					updates["responsibility"] = spec.Responsibility
				}
				if updateErr := db.Model(&model.AgentThread{}).
					Where("deployment_id = ? AND actor_id = ? AND project_id = ? AND id = ?", deploymentID, actorID, projectID, existing.ID).
					Updates(updates).Error; updateErr != nil {
					return fmt.Errorf("failed to backfill default %s thread instructions: %w", spec.ThreadPurpose, updateErr)
				}
			}
			defaultThreadIDs[spec.ThreadPurpose] = existing.ID
			continue
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to check default %s thread: %w", spec.ThreadPurpose, err)
		}

		threadID := idgen.NextID()
		systemInstructions, renderErr := buildProjectThreadSystemInstructions(project.Name, project.Description, spec.ThreadPurpose)
		if renderErr != nil {
			return renderErr
		}
		thread := model.AgentThread{
			Model:              model.Model{ID: threadID},
			DeploymentID:       deploymentID,
			ActorID:            actorID,
			ProjectID:          projectID,
			Title:              spec.Title,
			ThreadPurpose:      spec.ThreadPurpose,
			Responsibility:     spec.Responsibility,
			Reusable:           true,
			AcceptsAssignments: spec.AcceptsAssignments,
			CapabilityTags:     pq.StringArray{},
			Status:             model.ThreadStatusIdle,
			LastActivityAt:     now,
			SystemInstructions: &systemInstructions,
			Metadata:           json.RawMessage("{}"),
		}
		if err := db.Create(&thread).Error; err != nil {
			return fmt.Errorf("failed to create default %s thread: %w", spec.ThreadPurpose, err)
		}
		defaultThreadIDs[spec.ThreadPurpose] = thread.ID
	}

	projectUpdates := map[string]any{}
	if coordinatorID, ok := defaultThreadIDs["coordinator"]; ok {
		projectUpdates["coordinator_thread_id"] = coordinatorID
	}
	if reviewID, ok := defaultThreadIDs["review"]; ok {
		projectUpdates["review_thread_id"] = reviewID
	}
	if len(projectUpdates) > 0 {
		if err := db.Model(&model.ActorProject{}).
			Where("deployment_id = ? AND actor_id = ? AND id = ?", deploymentID, actorID, projectID).
			Updates(projectUpdates).Error; err != nil {
			return fmt.Errorf("failed to update project default thread references: %w", err)
		}
	}

	if selectedAgentID != nil && *selectedAgentID != 0 {
		if coordinatorID, ok := defaultThreadIDs[threadPurposeCoordinator]; ok {
			if err := s.upsertThreadAgentAssignment(db, coordinatorID, *selectedAgentID); err != nil {
				return fmt.Errorf("failed to bind coordinator thread agent: %w", err)
			}
		}
		if reviewID, ok := defaultThreadIDs[threadPurposeReview]; ok {
			if err := s.upsertThreadAgentAssignment(db, reviewID, *selectedAgentID); err != nil {
				return fmt.Errorf("failed to bind review thread agent: %w", err)
			}
		}
	}

	return nil
}

func (s *Service) upsertThreadAgentAssignment(db *gorm.DB, threadID, agentID uint64) error {
	now := time.Now()
	return db.Exec(`
			INSERT INTO thread_agent_assignments (thread_id, agent_id, created_at, updated_at)
		SELECT t.id, a.id, ?, ?
		FROM agent_threads t
		INNER JOIN ai_agents a
			ON a.id = ?
			AND a.deployment_id = t.deployment_id
		WHERE t.id = ?
		ON CONFLICT (thread_id)
		DO UPDATE SET
			agent_id = EXCLUDED.agent_id,
			updated_at = EXCLUDED.updated_at
		`, now, now, agentID, threadID).Error
}

func (s *Service) getThreadAgentAssignmentMap(threadIDs []uint64) (map[uint64]uint64, error) {
	if len(threadIDs) == 0 {
		return map[uint64]uint64{}, nil
	}

	var assignments []model.ThreadAgentAssignment
	if err := s.db.Where("thread_id IN ?", threadIDs).Find(&assignments).Error; err != nil {
		return nil, err
	}

	assignmentMap := make(map[uint64]uint64, len(assignments))
	for _, assignment := range assignments {
		assignmentMap[assignment.ThreadID] = assignment.AgentID
	}

	return assignmentMap, nil
}

func (s *Service) hydrateThreadAgentAssignment(thread *model.AgentThread) error {
	if thread == nil {
		return nil
	}

	assignmentMap, err := s.getThreadAgentAssignmentMap([]uint64{thread.ID})
	if err != nil {
		return err
	}

	if agentID, ok := assignmentMap[thread.ID]; ok {
		agentID := agentID
		thread.AgentID = &agentID
	} else {
		thread.AgentID = nil
	}

	return nil
}

func (s *Service) hydrateThreadAgentAssignments(threads []model.AgentThread) ([]model.AgentThread, error) {
	if len(threads) == 0 {
		return threads, nil
	}

	threadIDs := make([]uint64, 0, len(threads))
	for _, thread := range threads {
		threadIDs = append(threadIDs, thread.ID)
	}

	assignmentMap, err := s.getThreadAgentAssignmentMap(threadIDs)
	if err != nil {
		return nil, err
	}

	for index := range threads {
		if agentID, ok := assignmentMap[threads[index].ID]; ok {
			agentID := agentID
			threads[index].AgentID = &agentID
		} else {
			threads[index].AgentID = nil
		}
	}

	return threads, nil
}

func (s *Service) ListActorProjects(deploymentID, actorID uint64, includeArchived bool) ([]model.ActorProject, error) {
	var projects []model.ActorProject
	query := s.db.Where("deployment_id = ? AND actor_id = ?", deploymentID, actorID)
	if !includeArchived {
		query = query.Where("archived_at IS NULL")
	}
	if err := query.
		Order("updated_at DESC, id DESC").
		Find(&projects).Error; err != nil {
		return nil, err
	}
	return projects, nil
}

func (s *Service) SearchActorProjects(
	deploymentID, actorID uint64,
	query string,
	limit int,
	cursorUpdatedAt *time.Time,
	cursorID *uint64,
) (*ActorProjectsResponse, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	normalizedQuery := strings.ToLower(strings.TrimSpace(query))
	dbQuery := s.db.
		Where("deployment_id = ? AND actor_id = ? AND archived_at IS NULL", deploymentID, actorID)

	if normalizedQuery != "" {
		like := "%" + normalizedQuery + "%"
		dbQuery = dbQuery.Where("LOWER(name) LIKE ?", like)
	}
	if cursorUpdatedAt != nil && cursorID != nil {
		dbQuery = dbQuery.Where(
			"(updated_at < ? OR (updated_at = ? AND id < ?))",
			*cursorUpdatedAt,
			*cursorUpdatedAt,
			*cursorID,
		)
	}

	var projects []model.ActorProject
	if err := dbQuery.
		Order("updated_at DESC, id DESC").
		Limit(limit + 1).
		Find(&projects).Error; err != nil {
		return nil, err
	}

	hasMore := len(projects) > limit
	if hasMore {
		projects = projects[:limit]
	}

	nextCursor := ""
	if hasMore && len(projects) > 0 {
		last := projects[len(projects)-1]
		nextCursor = encodeUpdatedAtCursor(last.UpdatedAt, last.ID)
	}

	return &ActorProjectsResponse{
		Data:       projects,
		Limit:      limit,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

func (s *Service) GetActorProject(deploymentID, actorID, projectID uint64) (*model.ActorProject, error) {
	var project model.ActorProject
	if err := s.db.Where("deployment_id = ? AND actor_id = ? AND id = ?", deploymentID, actorID, projectID).First(&project).Error; err != nil {
		return nil, err
	}
	return &project, nil
}

func (s *Service) UpdateActorProject(deploymentID, actorID, projectID uint64, req UpdateActorProjectRequest) (*model.ActorProject, error) {
	project, err := s.GetActorProject(deploymentID, actorID, projectID)
	if err != nil {
		return nil, err
	}

	updates := map[string]any{}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name != "" {
			updates["name"] = name
		}
	}
	if req.Description != nil {
		description := strings.TrimSpace(*req.Description)
		if description == "" {
			updates["description"] = nil
		} else {
			updates["description"] = description
		}
	}
	if req.Status != nil {
		status := strings.TrimSpace(*req.Status)
		if status != "" {
			updates["status"] = status
		}
	}
	if len(updates) == 0 {
		return project, nil
	}

	if err := s.db.Model(&model.ActorProject{}).
		Where("deployment_id = ? AND actor_id = ? AND id = ?", deploymentID, actorID, projectID).
		Updates(updates).Error; err != nil {
		return nil, err
	}

	return s.GetActorProject(deploymentID, actorID, projectID)
}

func (s *Service) SetActorProjectArchived(deploymentID, actorID, projectID uint64, archived bool) (*model.ActorProject, error) {
	if _, err := s.GetActorProject(deploymentID, actorID, projectID); err != nil {
		return nil, err
	}

	updates := map[string]any{}
	if archived {
		now := time.Now()
		updates["archived_at"] = &now
	} else {
		updates["archived_at"] = nil
	}

	if err := s.db.Model(&model.ActorProject{}).
		Where("deployment_id = ? AND actor_id = ? AND id = ?", deploymentID, actorID, projectID).
		Updates(updates).Error; err != nil {
		return nil, err
	}

	return s.GetActorProject(deploymentID, actorID, projectID)
}

func (s *Service) GetRecentActorProject(deploymentID, actorID uint64) (*model.ActorProject, error) {
	var project model.ActorProject
	if err := s.db.Where("deployment_id = ? AND actor_id = ? AND archived_at IS NULL", deploymentID, actorID).
		Order("updated_at DESC").
		First(&project).Error; err != nil {
		return nil, err
	}
	return &project, nil
}

func (s *Service) ResolveRecentActorProject(
	deploymentID uint64,
	actorID uint64,
	ensureDefault bool,
) (*model.ActorProject, error) {
	return s.ResolveRecentActorProjectWithAgent(deploymentID, actorID, 0, ensureDefault)
}

func (s *Service) ResolveRecentActorProjectWithAgent(
	deploymentID uint64,
	actorID uint64,
	selectedAgentID uint64,
	ensureDefault bool,
) (*model.ActorProject, error) {
	project, err := s.GetRecentActorProject(deploymentID, actorID)
	if err == nil {
		return project, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if !ensureDefault {
		return nil, nil
	}
	return s.EnsureDefaultActorProjectWithAgent(deploymentID, actorID, selectedAgentID)
}

func (s *Service) CreateAgentThread(deploymentID, actorID, projectID uint64, req CreateAgentThreadRequest) (*model.AgentThread, error) {
	if _, err := s.GetActorProject(deploymentID, actorID, projectID); err != nil {
		return nil, fmt.Errorf("project not found or access denied")
	}

	threadID := idgen.NextID()
	thread := model.AgentThread{
		Model:              model.Model{ID: threadID},
		DeploymentID:       deploymentID,
		ActorID:            actorID,
		ProjectID:          projectID,
		Title:              strings.TrimSpace(req.Title),
		ThreadPurpose:      threadPurposeConversation,
		Reusable:           false,
		AcceptsAssignments: false,
		CapabilityTags:     pq.StringArray{},
		Status:             model.ThreadStatusIdle,
		LastActivityAt:     time.Now(),
		Metadata:           json.RawMessage("{}"),
		SystemInstructions: req.SystemInstructions,
	}
	if req.ThreadPurpose != nil && strings.TrimSpace(*req.ThreadPurpose) != "" {
		thread.ThreadPurpose = strings.TrimSpace(*req.ThreadPurpose)
	}
	if !isAllowedThreadPurpose(thread.ThreadPurpose) {
		return nil, fmt.Errorf("invalid thread purpose")
	}
	if req.Responsibility != nil && strings.TrimSpace(*req.Responsibility) != "" {
		responsibility := strings.TrimSpace(*req.Responsibility)
		thread.Responsibility = &responsibility
	}
	if req.Reusable != nil {
		thread.Reusable = *req.Reusable
	}
	if req.AcceptsAssignments != nil {
		thread.AcceptsAssignments = *req.AcceptsAssignments
	}
	if len(req.CapabilityTags) > 0 {
		thread.CapabilityTags = req.CapabilityTags
	}
	if len(req.Metadata) > 0 {
		thread.Metadata = req.Metadata
	}

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&thread).Error; err != nil {
			return err
		}
		if req.AgentID != nil && *req.AgentID != 0 {
			if err := s.upsertThreadAgentAssignment(tx, thread.ID, *req.AgentID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return s.GetThread(deploymentID, actorID, thread.ID)
}

func (s *Service) CreateActorThread(deploymentID, actorID uint64, req CreateAgentThreadRequest) (*model.AgentThread, error) {
	project, err := s.ResolveRecentActorProject(deploymentID, actorID, true)
	if err != nil {
		return nil, err
	}
	if project == nil {
		return nil, fmt.Errorf("failed to resolve project for thread creation")
	}
	return s.CreateAgentThread(deploymentID, actorID, project.ID, req)
}

func (s *Service) UpdateAgentThread(deploymentID, actorID, threadID uint64, req UpdateAgentThreadRequest) (*model.AgentThread, error) {
	thread, err := s.GetThread(deploymentID, actorID, threadID)
	if err != nil {
		return nil, err
	}
	updates := map[string]any{}
	if req.Title != nil {
		updates["title"] = strings.TrimSpace(*req.Title)
	}
	if req.SystemInstructions != nil {
		updates["system_instructions"] = *req.SystemInstructions
	}
	if len(updates) == 0 && req.AgentID == nil {
		return thread, nil
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if len(updates) > 0 {
			if err := tx.Model(&model.AgentThread{}).
				Where("deployment_id = ? AND actor_id = ? AND id = ?", deploymentID, actorID, threadID).
				Updates(updates).Error; err != nil {
				return err
			}
		}
		if req.AgentID != nil && *req.AgentID != 0 {
			if err := s.upsertThreadAgentAssignment(tx, threadID, *req.AgentID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s.GetThread(deploymentID, actorID, threadID)
}

func (s *Service) SetAgentThreadArchived(deploymentID, actorID, threadID uint64, archived bool) (*model.AgentThread, error) {
	thread, err := s.GetThread(deploymentID, actorID, threadID)
	if err != nil {
		return nil, err
	}
	if archived && (thread.ThreadPurpose == "execution" || thread.ThreadPurpose == "review") {
		return nil, ErrInternalThreadArchiveNotAllowed
	}

	updates := map[string]any{}
	if archived {
		now := time.Now()
		updates["archived_at"] = &now
	} else {
		updates["archived_at"] = nil
	}

	if err := s.db.Model(&model.AgentThread{}).
		Where("deployment_id = ? AND actor_id = ? AND id = ?", deploymentID, actorID, threadID).
		Updates(updates).Error; err != nil {
		return nil, err
	}

	return s.GetThread(deploymentID, actorID, threadID)
}

func (s *Service) ListProjectThreads(deploymentID, actorID, projectID uint64) ([]model.AgentThread, error) {
	var threads []model.AgentThread
	if err := s.db.Where("deployment_id = ? AND actor_id = ? AND project_id = ? AND archived_at IS NULL", deploymentID, actorID, projectID).
		Order("last_activity_at DESC").
		Find(&threads).Error; err != nil {
		return nil, err
	}
	return s.hydrateThreadAgentAssignments(threads)
}

func (s *Service) SearchProjectThreads(
	deploymentID, actorID, projectID uint64,
	query string,
	includeArchived bool,
	archivedOnly bool,
	limit int,
	cursorLastActivityAt *time.Time,
	cursorID *uint64,
) (*ProjectThreadsResponse, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	normalizedQuery := strings.ToLower(strings.TrimSpace(query))
	dbQuery := s.db.Where(
		"deployment_id = ? AND actor_id = ? AND project_id = ?",
		deploymentID,
		actorID,
		projectID,
	)
	switch {
	case archivedOnly:
		dbQuery = dbQuery.Where("archived_at IS NOT NULL")
	case !includeArchived:
		dbQuery = dbQuery.Where("archived_at IS NULL")
	}
	if normalizedQuery != "" {
		like := "%" + normalizedQuery + "%"
		dbQuery = dbQuery.Where("LOWER(title) LIKE ?", like)
	}
	if cursorLastActivityAt != nil && cursorID != nil {
		dbQuery = dbQuery.Where(
			"(last_activity_at < ? OR (last_activity_at = ? AND id < ?))",
			*cursorLastActivityAt,
			*cursorLastActivityAt,
			*cursorID,
		)
	}

	var threads []model.AgentThread
	if err := dbQuery.
		Order("last_activity_at DESC, id DESC").
		Limit(limit + 1).
		Find(&threads).Error; err != nil {
		return nil, err
	}

	hasMore := len(threads) > limit
	if hasMore {
		threads = threads[:limit]
	}

	hydratedThreads, err := s.hydrateThreadAgentAssignments(threads)
	if err != nil {
		return nil, err
	}

	nextCursor := ""
	if hasMore && len(hydratedThreads) > 0 {
		last := hydratedThreads[len(hydratedThreads)-1]
		nextCursor = encodeLastActivityCursor(last.LastActivityAt, last.ID)
	}

	return &ProjectThreadsResponse{
		Data:       hydratedThreads,
		Limit:      limit,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

func (s *Service) SearchActorThreads(
	deploymentID, actorID uint64,
	query string,
	limit int,
	cursorLastActivityAt *time.Time,
	cursorID *uint64,
) (*ProjectThreadsResponse, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	normalizedQuery := strings.ToLower(strings.TrimSpace(query))
	dbQuery := s.db.
		Model(&model.AgentThread{}).
		Select("agent_threads.*, actor_projects.name AS project_name").
		Joins("LEFT JOIN actor_projects ON actor_projects.id = agent_threads.project_id AND actor_projects.deployment_id = agent_threads.deployment_id").
		Where("agent_threads.deployment_id = ? AND agent_threads.actor_id = ? AND agent_threads.archived_at IS NULL", deploymentID, actorID)

	if normalizedQuery != "" {
		like := "%" + normalizedQuery + "%"
		dbQuery = dbQuery.Where("LOWER(agent_threads.title) LIKE ?", like)
	}
	if cursorLastActivityAt != nil && cursorID != nil {
		dbQuery = dbQuery.Where(
			"(agent_threads.last_activity_at < ? OR (agent_threads.last_activity_at = ? AND agent_threads.id < ?))",
			*cursorLastActivityAt,
			*cursorLastActivityAt,
			*cursorID,
		)
	}

	var threads []model.AgentThread
	if err := dbQuery.
		Order("agent_threads.last_activity_at DESC, agent_threads.id DESC").
		Limit(limit + 1).
		Find(&threads).Error; err != nil {
		return nil, err
	}

	hasMore := len(threads) > limit
	if hasMore {
		threads = threads[:limit]
	}

	hydratedThreads, err := s.hydrateThreadAgentAssignments(threads)
	if err != nil {
		return nil, err
	}

	nextCursor := ""
	if hasMore && len(hydratedThreads) > 0 {
		last := hydratedThreads[len(hydratedThreads)-1]
		nextCursor = encodeLastActivityCursor(last.LastActivityAt, last.ID)
	}

	return &ProjectThreadsResponse{
		Data:       hydratedThreads,
		Limit:      limit,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

func (s *Service) GetThread(deploymentID, actorID, threadID uint64) (*model.AgentThread, error) {
	var thread model.AgentThread
	if err := s.db.Where("deployment_id = ? AND actor_id = ? AND id = ?", deploymentID, actorID, threadID).First(&thread).Error; err != nil {
		return nil, err
	}
	if err := s.hydrateThreadAgentAssignment(&thread); err != nil {
		return nil, err
	}
	return &thread, nil
}

func extractMetadata(messageType string) json.RawMessage {
	metadata := map[string]string{
		"message_type": messageType,
	}
	data, _ := json.Marshal(metadata)
	return data
}

func (s *Service) GetThreadMessages(
	deploymentID uint64,
	actorID uint64,
	threadID uint64,
	limit int,
	beforeID, afterID string,
) ([]ConversationMessage, bool, error) {
	if _, err := s.GetThread(deploymentID, actorID, threadID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, false, fmt.Errorf("thread not found or access denied")
		}
		return nil, false, fmt.Errorf("failed to fetch thread: %w", err)
	}

	messagesQuery := s.db.Model(&model.Conversation{}).
		Select("id, thread_id, execution_run_id, message_type, content - 'thought_signature' as content, timestamp, metadata, created_at, updated_at").
		Where("thread_id = ?", threadID)

	if beforeID != "" {
		messagesQuery = messagesQuery.Where("id < ?", beforeID)
	}
	if afterID != "" {
		messagesQuery = messagesQuery.Where("id > ?", afterID).Order("id ASC")
	} else {
		messagesQuery = messagesQuery.Order("id DESC")
	}

	messagesQuery = messagesQuery.Limit(limit + 1)

	var conversations []model.Conversation
	if err := messagesQuery.Find(&conversations).Error; err != nil {
		return nil, false, fmt.Errorf("failed to fetch messages: %w", err)
	}

	hasMore := len(conversations) > limit
	if hasMore {
		conversations = conversations[:limit]
	}

	if afterID != "" {
		for i := len(conversations)/2 - 1; i >= 0; i-- {
			opp := len(conversations) - 1 - i
			conversations[i], conversations[opp] = conversations[opp], conversations[i]
		}
	}

	messages := make([]ConversationMessage, len(conversations))
	for i, conv := range conversations {
		messages[i] = ConversationMessage{
			ID:        fmt.Sprintf("%d", conv.ID),
			Content:   conv.Content,
			Timestamp: conv.Timestamp,
			Metadata:  extractMetadata(conv.MessageType),
		}
	}

	return messages, hasMore, nil
}

func (s *Service) GetProjectBoard(deploymentID, actorID, projectID uint64) (*model.ProjectTaskBoard, error) {
	var board model.ProjectTaskBoard
	result := s.db.Where("deployment_id = ? AND actor_id = ? AND project_id = ? AND archived_at IS NULL", deploymentID, actorID, projectID).
		Order("updated_at DESC").
		Limit(1).
		Find(&board)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &board, nil
}

func (s *Service) EnsureProjectBoard(deploymentID, actorID, projectID uint64) (*model.ProjectTaskBoard, error) {
	board, err := s.GetProjectBoard(deploymentID, actorID, projectID)
	if err == nil {
		return board, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	project, err := s.GetActorProject(deploymentID, actorID, projectID)
	if err != nil {
		return nil, err
	}

	title := "Project Board"
	if name := strings.TrimSpace(project.Name); name != "" {
		title = fmt.Sprintf("%s Board", name)
	}

	board = &model.ProjectTaskBoard{
		Model:        model.Model{ID: idgen.NextID()},
		DeploymentID: deploymentID,
		ActorID:      actorID,
		ProjectID:    projectID,
		Title:        title,
		Status:       "active",
		Metadata:     json.RawMessage("{}"),
	}

	if err := s.db.Create(board).Error; err != nil {
		if !strings.Contains(err.Error(), "duplicate key") {
			return nil, err
		}
		return s.GetProjectBoard(deploymentID, actorID, projectID)
	}

	return board, nil
}

func (s *Service) GetProjectBoardByID(deploymentID, actorID, boardID uint64) (*model.ProjectTaskBoard, error) {
	var board model.ProjectTaskBoard
	if err := s.db.Where("deployment_id = ? AND actor_id = ? AND id = ? AND archived_at IS NULL", deploymentID, actorID, boardID).
		First(&board).Error; err != nil {
		return nil, err
	}
	return &board, nil
}

func (s *Service) ListProjectBoardItems(
	boardID uint64,
	statuses []string,
	includeArchived bool,
	archivedOnly bool,
	limit int,
	cursorCreatedAt *time.Time,
	cursorID *uint64,
) (*ProjectTaskBoardItemsResponse, error) {
	if limit <= 0 {
		limit = 60
	}
	if limit > 200 {
		limit = 200
	}

	var items []model.ProjectTaskBoardItem
	query := s.db.Where("board_id = ?", boardID)
	switch {
	case archivedOnly:
		query = query.Where("archived_at IS NOT NULL")
	case !includeArchived:
		query = query.Where("archived_at IS NULL")
	}
	if len(statuses) > 0 {
		query = query.Where("status IN ?", statuses)
	}
	if cursorCreatedAt != nil && cursorID != nil {
		query = query.Where(
			"(created_at < ? OR (created_at = ? AND id < ?))",
			*cursorCreatedAt,
			*cursorCreatedAt,
			*cursorID,
		)
	}
	if err := query.
		Order("created_at DESC").
		Order("id DESC").
		Limit(limit + 1).
		Find(&items).Error; err != nil {
		return nil, err
	}

	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}

	if err := s.attachProjectTaskSchedules(s.db, items); err != nil {
		return nil, err
	}

	nextCursor := ""
	if hasMore && len(items) > 0 {
		last := items[len(items)-1]
		nextCursor = base64.RawURLEncoding.EncodeToString(
			[]byte(fmt.Sprintf("%d|%d", last.CreatedAt.UnixNano(), last.ID)),
		)
	}

	return &ProjectTaskBoardItemsResponse{
		Data:       items,
		Limit:      limit,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

func (s *Service) GetBoardItem(itemID uint64, includeArchived bool) (*model.ProjectTaskBoardItem, error) {
	var item model.ProjectTaskBoardItem
	query := s.db.Where("id = ?", itemID)
	if !includeArchived {
		query = query.Where("archived_at IS NULL")
	}
	if err := query.First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *Service) GetAuthorizedBoardItem(deploymentID, actorID, itemID uint64, includeArchived bool) (*model.ProjectTaskBoardItem, error) {
	item, err := s.GetBoardItem(itemID, includeArchived)
	if err != nil {
		return nil, err
	}
	if _, err := s.GetProjectBoardByID(deploymentID, actorID, item.BoardID); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *Service) GetBoardItemDetail(deploymentID, actorID, itemID uint64, includeArchived bool) (*ProjectTaskBoardItemDetail, error) {
type boardItemDetailRow struct {
		Item        json.RawMessage `gorm:"column:item"`
		Events      json.RawMessage `gorm:"column:events"`
		Assignments json.RawMessage `gorm:"column:assignments"`
		Schedule    json.RawMessage `gorm:"column:schedule"`
	}

	var row boardItemDetailRow
	if err := s.db.Raw(`
		SELECT
			row_to_json(item_row) AS item,
			COALESCE((
				SELECT json_agg(row_to_json(event_row) ORDER BY event_row.created_at ASC)
				FROM (
					SELECT
						e.id::text AS id,
						e.board_item_id::text AS board_item_id,
						CASE WHEN e.thread_id IS NULL THEN NULL ELSE e.thread_id::text END AS thread_id,
						CASE WHEN e.execution_run_id IS NULL THEN NULL ELSE e.execution_run_id::text END AS execution_run_id,
						e.event_type,
						e.summary,
						e.body_markdown,
						e.details,
						e.created_at
					FROM project_task_board_item_events e
					WHERE e.board_item_id = item_row.raw_id
					ORDER BY e.created_at ASC
				) AS event_row
			), '[]'::json) AS events,
			COALESCE((
				SELECT json_agg(row_to_json(assignment_row) ORDER BY assignment_row.assignment_order ASC, assignment_row.created_at ASC)
				FROM (
					SELECT
						a.id::text AS id,
						a.board_item_id::text AS board_item_id,
						a.thread_id::text AS thread_id,
						a.assignment_role,
						a.assignment_order,
						a.status,
						a.instructions,
						a.handoff_file_path,
						a.metadata,
						a.result_status,
						a.result_summary,
						a.result_payload,
						a.claimed_at,
						a.started_at,
						a.completed_at,
						a.rejected_at,
						a.created_at,
						a.updated_at
					FROM project_task_board_item_assignments a
					WHERE a.board_item_id = item_row.raw_id
					ORDER BY a.assignment_order ASC, a.created_at ASC
				) AS assignment_row
			), '[]'::json) AS assignments,
			(
				SELECT row_to_json(schedule_row)
				FROM (
					SELECT
						s.id::text AS id,
						s.template_board_item_id::text AS template_board_item_id,
						s.status,
						s.schedule_kind,
						s.interval_seconds,
						s.next_run_at,
						s.last_enqueued_at,
						s.created_at,
						s.updated_at
					FROM project_task_schedules s
					WHERE s.template_board_item_id = item_row.raw_id
					LIMIT 1
				) AS schedule_row
			) AS schedule
		FROM (
			SELECT
				i.id AS raw_id,
				i.id::text AS id,
				i.board_id::text AS board_id,
				i.task_key,
				i.title,
				i.description,
				i.status,
				i.priority,
				CASE WHEN i.assigned_thread_id IS NULL THEN NULL ELSE i.assigned_thread_id::text END AS assigned_thread_id,
				i.metadata,
				i.completed_at,
				i.archived_at,
				i.created_at,
				i.updated_at
			FROM project_task_board_items i
			INNER JOIN project_task_boards b ON b.id = i.board_id
			WHERE i.id = ?
				AND b.deployment_id = ?
				AND b.actor_id = ?
				AND (? OR i.archived_at IS NULL)
			LIMIT 1
		) AS item_row
	`, itemID, deploymentID, actorID, includeArchived).Scan(&row).Error; err != nil {
		return nil, err
	}

	if len(row.Item) == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	detail := &ProjectTaskBoardItemDetail{}
	if err := json.Unmarshal(row.Item, &detail.Item); err != nil {
		return nil, err
	}
	if len(row.Events) > 0 {
		if err := json.Unmarshal(row.Events, &detail.Events); err != nil {
			return nil, err
		}
	}
	if len(row.Assignments) > 0 {
		if err := json.Unmarshal(row.Assignments, &detail.Assignments); err != nil {
			return nil, err
		}
	}
	if len(row.Schedule) > 0 && string(row.Schedule) != "null" {
		var schedule model.ProjectTaskSchedule
		if err := json.Unmarshal(row.Schedule, &schedule); err != nil {
			return nil, err
		}
		detail.Item.Schedule = &schedule
	}
	if detail.Events == nil {
		detail.Events = []model.ProjectTaskBoardItemEvent{}
	}
	if detail.Assignments == nil {
		detail.Assignments = []model.ProjectTaskBoardItemAssignment{}
	}

	return detail, nil
}

func parseOptionalUint64(value *string) (*uint64, error) {
	if value == nil {
		return nil, nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func normalizeJSON(raw json.RawMessage, fallback string) json.RawMessage {
	if len(raw) == 0 {
		if fallback == "" {
			return nil
		}
		return json.RawMessage(fallback)
	}
	return raw
}

func decodeJSONObject(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}

	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}

	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("metadata must be a JSON object")
	}
	return object, nil
}

func mergeTaskBoardItemMetadata(
	existingRaw json.RawMessage,
	requestedRaw json.RawMessage,
	attachments []UploadedTaskWorkspaceFile,
) (json.RawMessage, error) {
	merged, err := decodeJSONObject(existingRaw)
	if err != nil {
		return nil, err
	}

	if len(requestedRaw) > 0 {
		requested, err := decodeJSONObject(requestedRaw)
		if err != nil {
			return nil, err
		}
		for key, value := range requested {
			merged[key] = value
		}
	}

	if len(attachments) > 0 {
		attachmentItems := make([]any, 0, len(attachments))
		if existing, ok := merged["attachments"].([]any); ok {
			attachmentItems = append(attachmentItems, existing...)
		}
		for _, attachment := range attachments {
			attachmentItems = append(attachmentItems, attachment)
		}
		merged["attachments"] = attachmentItems
	}

	payload, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	return normalizeJSON(payload, "{}"), nil
}

func buildTaskAttachmentEventBody(prefix string, attachments []UploadedTaskWorkspaceFile) *string {
	if len(attachments) == 0 {
		return nil
	}

	lines := make([]string, 0, len(attachments)+2)
	if trimmed := strings.TrimSpace(prefix); trimmed != "" {
		lines = append(lines, trimmed, "")
	}
	lines = append(lines, "Uploaded files:")
	for _, attachment := range attachments {
		path := strings.TrimSpace(attachment.Path)
		if path == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("- [`%s`](%s)", path, path))
	}

	body := strings.TrimSpace(strings.Join(lines, "\n"))
	if body == "" {
		return nil
	}
	return &body
}

func normalizeTaskPriority(value *string) string {
	if value == nil {
		return taskPriorityNeutral
	}

	switch strings.ToLower(strings.TrimSpace(*value)) {
	case taskPriorityUrgent:
		return taskPriorityUrgent
	case taskPriorityHigh:
		return taskPriorityHigh
	case taskPriorityLow:
		return taskPriorityLow
	default:
		return taskPriorityNeutral
	}
}

func matchesStatus(status string, values ...string) bool {
	for _, value := range values {
		if status == value {
			return true
		}
	}
	return false
}

func assignmentEventDetailsJSON(assignment *model.ProjectTaskBoardItemAssignment, note *string) json.RawMessage {
	details, _ := json.Marshal(map[string]any{
		"assignment_id":     assignment.ID,
		"board_item_id":     assignment.BoardItemID,
		"thread_id":         assignment.ThreadID,
		"assignment_role":   assignment.AssignmentRole,
		"assignment_order":  assignment.AssignmentOrder,
		"status":            assignment.Status,
		"result_status":     assignment.ResultStatus,
		"result_summary":    assignment.ResultSummary,
		"result_payload":    json.RawMessage(assignment.ResultPayload),
		"note":              note,
		"instructions":      assignment.Instructions,
		"handoff_file_path": assignment.HandoffFilePath,
		"metadata":          json.RawMessage(assignment.Metadata),
	})
	return normalizeJSON(details, "{}")
}

func (s *Service) createBoardItemEvent(tx *gorm.DB, boardItemID uint64, threadID *uint64, eventType, summary string, bodyMarkdown *string, details json.RawMessage) error {
	event := model.ProjectTaskBoardItemEvent{
		ID:           idgen.NextID(),
		BoardItemID:  boardItemID,
		ThreadID:     threadID,
		EventType:    eventType,
		Summary:      summary,
		BodyMarkdown: bodyMarkdown,
		Details:      normalizeJSON(details, "{}"),
		CreatedAt:    time.Now(),
	}
	return tx.Create(&event).Error
}

func (s *Service) upsertThreadWorkEvent(tx *gorm.DB, deploymentID, threadID uint64, boardItemID *uint64, eventType string, priority int, payload json.RawMessage, causedByThreadID *uint64) (*model.ThreadEvent, error) {
	now := time.Now()
	var event model.ThreadEvent
	if err := tx.Raw(`
		INSERT INTO thread_events (
			id, deployment_id, thread_id, board_item_id, event_type, status,
			priority, payload, available_at, claimed_at, completed_at, failed_at,
			caused_by_conversation_id, caused_by_run_id, caused_by_thread_id, created_at, updated_at
		) VALUES (
			?, ?, ?, ?, ?, 'pending',
			?, ?, ?, NULL, NULL, NULL,
			NULL, NULL, ?, ?, ?
		)
		ON CONFLICT (thread_id, event_type, board_item_id)
		WHERE board_item_id IS NOT NULL
			AND status = 'pending'
			AND event_type IN ('task_routing', 'assignment_execution', 'assignment_outcome_review')
		DO UPDATE SET
			priority = LEAST(thread_events.priority, EXCLUDED.priority),
			payload = EXCLUDED.payload,
			available_at = LEAST(thread_events.available_at, EXCLUDED.available_at),
			updated_at = EXCLUDED.updated_at
		RETURNING
			id, deployment_id, thread_id, board_item_id, event_type, status,
			priority, payload, available_at, claimed_at, completed_at, failed_at,
			caused_by_conversation_id, caused_by_run_id, caused_by_thread_id, created_at, updated_at
	`, idgen.NextID(), deploymentID, threadID, boardItemID, eventType, priority, normalizeJSON(payload, "{}"), now, causedByThreadID, now, now).Scan(&event).Error; err != nil {
		return nil, err
	}
	return &event, nil
}

func (s *Service) enqueueAssignmentExecutionEvent(tx *gorm.DB, deploymentID uint64, assignment *model.ProjectTaskBoardItemAssignment) (*model.ThreadEvent, error) {
	return s.upsertThreadWorkEvent(
		tx,
		deploymentID,
		assignment.ThreadID,
		&assignment.BoardItemID,
		"assignment_execution",
		20,
		assignmentEventDetailsJSON(assignment, nil),
		nil,
	)
}

func (s *Service) enqueueTaskRoutingEvent(tx *gorm.DB, deploymentID, threadID uint64, item *model.ProjectTaskBoardItem) (*model.ThreadEvent, error) {
	payload, _ := json.Marshal(map[string]any{
		"board_item_id":      item.ID,
		"task_key":           item.TaskKey,
		"title":              item.Title,
		"description":        item.Description,
		"status":             item.Status,
		"priority":           item.Priority,
		"assigned_thread_id": item.AssignedThreadID,
	})
	return s.upsertThreadWorkEvent(
		tx,
		deploymentID,
		threadID,
		&item.ID,
		"task_routing",
		30,
		normalizeJSON(payload, "{}"),
		nil,
	)
}

func (s *Service) maybePublishThreadEventExecution(event *model.ThreadEvent) error {
	natsService := service.GetNATS()
	if natsService == nil {
		return nil
	}
	return natsService.PublishThreadSchedule(context.Background(), event.DeploymentID, event.ThreadID)
}

func (s *Service) CreateProjectBoardItem(
	deploymentID, actorID, projectID uint64,
	req CreateProjectTaskBoardItemRequest,
	files []*multipart.FileHeader,
) (*model.ProjectTaskBoardItem, error) {
	project, err := s.GetActorProject(deploymentID, actorID, projectID)
	if err != nil {
		return nil, fmt.Errorf("project not found or access denied")
	}
	board, err := s.EnsureProjectBoard(deploymentID, actorID, projectID)
	if err != nil {
		return nil, err
	}

	if project.CoordinatorThreadID == nil {
		return nil, fmt.Errorf("project coordinator thread is not configured")
	}
	assignedThreadID := project.CoordinatorThreadID

	itemID := idgen.NextID()
	taskKey := strings.TrimSpace(fmt.Sprintf("TASK-%d", itemID))
	attachments, err := uploadTaskWorkspaceFilesForTaskKey(deploymentID, projectID, taskKey, files)
	if err != nil {
		return nil, err
	}
	status := "pending"
	if req.Status != nil && strings.TrimSpace(*req.Status) != "" {
		status = strings.TrimSpace(*req.Status)
	}
	priority := normalizeTaskPriority(req.Priority)
	schedule, err := parseTaskScheduleRequest(req.ScheduleKind, req.NextRunAt, req.IntervalSeconds)
	if err != nil {
		return nil, err
	}
	metadata, err := mergeTaskBoardItemMetadata(nil, nil, attachments)
	if err != nil {
		return nil, err
	}

	item := &model.ProjectTaskBoardItem{
		Model:            model.Model{ID: itemID},
		BoardID:          board.ID,
		TaskKey:          taskKey,
		Title:            strings.TrimSpace(req.Title),
		Description:      req.Description,
		Status:           status,
		Priority:         priority,
		AssignedThreadID: assignedThreadID,
		Metadata:         metadata,
	}
	if status == "completed" {
		now := time.Now()
		item.CompletedAt = &now
	}

	var threadEvent *model.ThreadEvent
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(item).Error; err != nil {
			return err
		}
		if err := s.reconcileProjectTaskSchedule(tx, item.ID, schedule, false); err != nil {
			return err
		}
		details, _ := json.Marshal(map[string]any{
			"board_id":           item.BoardID,
			"task_key":           item.TaskKey,
			"status":             item.Status,
			"assigned_thread_id": item.AssignedThreadID,
			"priority":           item.Priority,
			"attachments":        attachments,
		})
		bodyMarkdown := buildTaskAttachmentEventBody("Task created with workspace uploads.", attachments)
		if err := s.createBoardItemEvent(tx, item.ID, item.AssignedThreadID, "task_created", "Task created", bodyMarkdown, details); err != nil {
			return err
		}
		threadEvent, err = s.enqueueTaskRoutingEvent(tx, deploymentID, *assignedThreadID, item)
		return err
	}); err != nil {
		return nil, err
	}

	if threadEvent != nil {
		if err := s.maybePublishThreadEventExecution(threadEvent); err != nil {
			return nil, err
		}
	}

	if err := s.attachProjectTaskSchedule(s.db, item); err != nil {
		return nil, err
	}

	return item, nil
}

func (s *Service) UpdateProjectBoardItem(
	deploymentID, actorID, itemID uint64,
	req UpdateProjectTaskBoardItemRequest,
	files []*multipart.FileHeader,
) (*model.ProjectTaskBoardItem, error) {
	item, err := s.GetAuthorizedBoardItem(deploymentID, actorID, itemID, false)
	if err != nil {
		return nil, err
	}
	board, err := s.GetProjectBoardByID(deploymentID, actorID, item.BoardID)
	if err != nil {
		return nil, err
	}
	project, err := s.GetActorProject(deploymentID, actorID, board.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("project not found or access denied")
	}

	attachments, err := uploadTaskWorkspaceFilesForTaskKey(deploymentID, board.ProjectID, item.TaskKey, files)
	if err != nil {
		return nil, err
	}
	schedule, err := parseTaskScheduleRequest(req.ScheduleKind, req.NextRunAt, req.IntervalSeconds)
	if err != nil {
		return nil, err
	}
	clearSchedule := req.ClearSchedule != nil && *req.ClearSchedule
	if clearSchedule && schedule != nil {
		return nil, fmt.Errorf("clear_schedule cannot be combined with schedule fields")
	}

	updates := map[string]any{}
	details := map[string]any{}

	if req.Title != nil {
		title := strings.TrimSpace(*req.Title)
		updates["title"] = title
		details["title"] = title
		item.Title = title
	}
	if req.Description != nil {
		updates["description"] = req.Description
		details["description"] = req.Description
		item.Description = req.Description
	}
	if req.Status != nil && strings.TrimSpace(*req.Status) != "" {
		status := strings.TrimSpace(*req.Status)
		updates["status"] = status
		details["status"] = status
		item.Status = status
		if status == "completed" {
			now := time.Now()
			updates["completed_at"] = &now
			item.CompletedAt = &now
		} else {
			updates["completed_at"] = nil
			item.CompletedAt = nil
		}
	}
	if req.Priority != nil {
		priority := normalizeTaskPriority(req.Priority)
		updates["priority"] = priority
		details["priority"] = priority
		item.Priority = priority
	}
	if len(attachments) > 0 {
		metadata, err := mergeTaskBoardItemMetadata(item.Metadata, nil, attachments)
		if err != nil {
			return nil, err
		}
		updates["metadata"] = metadata
		details["metadata"] = json.RawMessage(metadata)
		item.Metadata = metadata
	}
	if len(attachments) > 0 {
		details["attachments"] = attachments
	}

	if len(updates) == 0 && schedule == nil && !clearSchedule {
		if err := s.attachProjectTaskSchedule(s.db, item); err != nil {
			return nil, err
		}
		return item, nil
	}

	var threadEvent *model.ThreadEvent
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.ProjectTaskBoardItem{}).Where("id = ?", itemID).Updates(updates).Error; err != nil {
			return err
		}
		if err := s.reconcileProjectTaskSchedule(tx, item.ID, schedule, clearSchedule); err != nil {
			return err
		}
		detailsJSON, _ := json.Marshal(details)
		bodyMarkdown := buildTaskAttachmentEventBody("Task updated with workspace uploads.", attachments)
		if err := s.createBoardItemEvent(tx, itemID, item.AssignedThreadID, "task_updated", "Task updated", bodyMarkdown, detailsJSON); err != nil {
			return err
		}
		if project.CoordinatorThreadID != nil {
			threadEvent, err = s.enqueueTaskRoutingEvent(tx, deploymentID, *project.CoordinatorThreadID, item)
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if threadEvent != nil {
		if err := s.maybePublishThreadEventExecution(threadEvent); err != nil {
			return nil, err
		}
	}

	updatedItem, err := s.GetAuthorizedBoardItem(deploymentID, actorID, itemID, true)
	if err != nil {
		return nil, err
	}
	if err := s.attachProjectTaskSchedule(s.db, updatedItem); err != nil {
		return nil, err
	}
	return updatedItem, nil
}

func (s *Service) ArchiveProjectBoardItem(deploymentID, actorID, itemID uint64) (*model.ProjectTaskBoardItem, error) {
	now := time.Now()
	eventID := idgen.NextID()
	type archiveResultRow struct {
		Item json.RawMessage `gorm:"column:item"`
	}
	var row archiveResultRow

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		return tx.Raw(`
			WITH target AS (
				SELECT
					i.id,
					i.assigned_thread_id,
					EXISTS (
						SELECT 1
						FROM project_task_board_item_assignments a
						WHERE a.board_item_id = i.id
							AND a.status IN ('claimed', 'in_progress', 'completed')
					) AS picked
				FROM project_task_board_items i
				INNER JOIN project_task_boards b ON b.id = i.board_id
				WHERE i.id = ?
					AND b.deployment_id = ?
					AND b.actor_id = ?
					AND i.archived_at IS NULL
				FOR UPDATE
			),
			updated_item AS (
				UPDATE project_task_board_items i
				SET
					archived_at = ?,
					updated_at = ?,
					assigned_thread_id = CASE
						WHEN (SELECT picked FROM target) THEN i.assigned_thread_id
						ELSE NULL
					END
				WHERE i.id = (SELECT id FROM target)
				RETURNING i.*
			),
			cancelled_assignments AS (
				UPDATE project_task_board_item_assignments a
				SET
					status = 'cancelled',
					updated_at = ?
				WHERE a.board_item_id = (SELECT id FROM target)
					AND NOT (SELECT picked FROM target)
					AND a.status IN ('pending', 'available')
				RETURNING 1
			),
			cancelled_events AS (
				UPDATE thread_events e
				SET
					status = 'cancelled',
					updated_at = ?
				WHERE e.board_item_id = (SELECT id FROM target)
					AND NOT (SELECT picked FROM target)
					AND e.status = 'pending'
					AND e.event_type IN ('task_routing', 'assignment_execution', 'assignment_outcome_review')
				RETURNING 1
			),
			inserted_event AS (
				INSERT INTO project_task_board_item_events (
					id,
					board_item_id,
					thread_id,
					event_type,
					summary,
					details,
					created_at
				)
				SELECT
					?,
					t.id,
					t.assigned_thread_id,
					'task_archived',
					'Task archived',
					json_build_object(
						'picked', t.picked,
						'cancelled_assignments', COALESCE((SELECT COUNT(*) FROM cancelled_assignments), 0),
						'cancelled_thread_events', COALESCE((SELECT COUNT(*) FROM cancelled_events), 0)
					),
					?
				FROM target t
				RETURNING 1
			)
			SELECT row_to_json(u) AS item
			FROM updated_item u
		`, itemID, deploymentID, actorID, now, now, now, now, eventID, now).Scan(&row).Error
	}); err != nil {
		return nil, err
	}

	if len(row.Item) == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	var item model.ProjectTaskBoardItem
	if err := json.Unmarshal(row.Item, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *Service) UnarchiveProjectBoardItem(deploymentID, actorID, itemID uint64) (*model.ProjectTaskBoardItem, error) {
	now := time.Now()
	eventID := idgen.NextID()
	type unarchiveResultRow struct {
		Item json.RawMessage `gorm:"column:item"`
	}
	var row unarchiveResultRow

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		return tx.Raw(`
			WITH target AS (
				SELECT
					i.id,
					i.assigned_thread_id,
					i.archived_at
				FROM project_task_board_items i
				INNER JOIN project_task_boards b ON b.id = i.board_id
				WHERE i.id = ?
					AND b.deployment_id = ?
					AND b.actor_id = ?
					AND i.archived_at IS NOT NULL
				FOR UPDATE
			),
			updated_item AS (
				UPDATE project_task_board_items i
				SET
					archived_at = NULL,
					updated_at = ?
				WHERE i.id = (SELECT id FROM target)
				RETURNING i.*
			),
			inserted_event AS (
				INSERT INTO project_task_board_item_events (
					id,
					board_item_id,
					thread_id,
					event_type,
					summary,
					details,
					created_at
				)
				SELECT
					?,
					t.id,
					t.assigned_thread_id,
					'task_unarchived',
					'Task unarchived',
					json_build_object('previous_archived_at', t.archived_at),
					?
				FROM target t
				RETURNING 1
			)
			SELECT row_to_json(u) AS item
			FROM updated_item u
		`, itemID, deploymentID, actorID, now, eventID, now).Scan(&row).Error
	}); err != nil {
		return nil, err
	}

	if len(row.Item) == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	var item model.ProjectTaskBoardItem
	if err := json.Unmarshal(row.Item, &item); err != nil {
		return nil, err
	}

	board, err := s.GetProjectBoardByID(deploymentID, actorID, item.BoardID)
	if err != nil {
		return nil, err
	}
	project, err := s.GetActorProject(deploymentID, actorID, board.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("project not found or access denied")
	}
	if project.CoordinatorThreadID != nil {
		var threadEvent *model.ThreadEvent
		if err := s.db.Transaction(func(tx *gorm.DB) error {
			var enqueueErr error
			threadEvent, enqueueErr = s.enqueueTaskRoutingEvent(tx, deploymentID, *project.CoordinatorThreadID, &item)
			return enqueueErr
		}); err != nil {
			return nil, err
		}
		if threadEvent != nil {
			if err := s.maybePublishThreadEventExecution(threadEvent); err != nil {
				return nil, err
			}
		}
	}
	return &item, nil
}

func (s *Service) AppendBoardItemJournalEntry(
	deploymentID, actorID, itemID uint64,
	summary string,
	details *string,
	bodyMarkdown *string,
	attachments []UploadedTaskWorkspaceFile,
) (*model.ProjectTaskBoardItemEvent, error) {
	item, err := s.GetAuthorizedBoardItem(deploymentID, actorID, itemID, false)
	if err != nil {
		return nil, err
	}

	summary = strings.TrimSpace(summary)
	if summary == "" {
		return nil, fmt.Errorf("summary must not be empty")
	}

	var normalizedBody *string
	if bodyMarkdown != nil {
		trimmed := strings.TrimSpace(*bodyMarkdown)
		if trimmed != "" {
			normalizedBody = &trimmed
		}
	}
	if normalizedBody == nil && details != nil {
		trimmed := strings.TrimSpace(*details)
		if trimmed != "" {
			normalizedBody = &trimmed
		}
	}

	detailsJSON, _ := json.Marshal(map[string]any{
		"task_key":    item.TaskKey,
		"details":     normalizedBody,
		"attachments": attachments,
	})

	board, err := s.GetProjectBoardByID(deploymentID, actorID, item.BoardID)
	if err != nil {
		return nil, err
	}
	project, err := s.GetActorProject(deploymentID, actorID, board.ProjectID)
	if err != nil {
		return nil, err
	}

	var event model.ProjectTaskBoardItemEvent
	var threadEvent *model.ThreadEvent
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		event = model.ProjectTaskBoardItemEvent{
			ID:           idgen.NextID(),
			BoardItemID:  item.ID,
			EventType:    "task_journal_entry",
			Summary:      summary,
			BodyMarkdown: normalizedBody,
			Details:      normalizeJSON(detailsJSON, "{}"),
			CreatedAt:    time.Now(),
		}
		if err := tx.Create(&event).Error; err != nil {
			return err
		}

		if (item.Status == "blocked" || item.Status == "needs_clarification") && project.CoordinatorThreadID != nil {
			threadEvent, err = s.enqueueTaskRoutingEvent(tx, deploymentID, *project.CoordinatorThreadID, item)
			if err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	if threadEvent != nil {
		if err := s.maybePublishThreadEventExecution(threadEvent); err != nil {
			return nil, err
		}
	}

	return &event, nil
}

func (s *Service) ListBoardItemAssignments(itemID uint64) ([]model.ProjectTaskBoardItemAssignment, error) {
	var assignments []model.ProjectTaskBoardItemAssignment
	if err := s.db.Where("board_item_id = ?", itemID).Order("assignment_order ASC, created_at ASC").Find(&assignments).Error; err != nil {
		return nil, err
	}
	return assignments, nil
}

func (s *Service) GetBoardItemAssignment(assignmentID uint64) (*model.ProjectTaskBoardItemAssignment, error) {
	var assignment model.ProjectTaskBoardItemAssignment
	if err := s.db.Where("id = ?", assignmentID).First(&assignment).Error; err != nil {
		return nil, err
	}
	return &assignment, nil
}

func (s *Service) GetAuthorizedBoardItemAssignment(deploymentID, actorID, assignmentID uint64) (*model.ProjectTaskBoardItemAssignment, error) {
	assignment, err := s.GetBoardItemAssignment(assignmentID)
	if err != nil {
		return nil, err
	}
	if _, err := s.GetAuthorizedBoardItem(deploymentID, actorID, assignment.BoardItemID, false); err != nil {
		return nil, err
	}
	return assignment, nil
}

func encodeThreadEventCursor(createdAt time.Time, eventID uint64) string {
	raw := fmt.Sprintf("%d|%d", createdAt.UnixNano(), eventID)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func encodeUpdatedAtCursor(updatedAt time.Time, id uint64) string {
	raw := fmt.Sprintf("%d|%d", updatedAt.UnixNano(), id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func encodeLastActivityCursor(lastActivityAt time.Time, threadID uint64) string {
	raw := fmt.Sprintf("%d|%d", lastActivityAt.UnixNano(), threadID)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func encodeThreadAssignmentCursor(assignmentOrder int, assignmentID uint64) string {
	raw := fmt.Sprintf("%d|%d", assignmentOrder, assignmentID)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func (s *Service) ListThreadAssignments(
	threadID uint64,
	limit int,
	cursorAssignmentOrder *int,
	cursorID *uint64,
) (*ThreadAssignmentsResponse, error) {
	if limit <= 0 {
		limit = 40
	}
	if limit > 200 {
		limit = 200
	}

	var assignments []model.ProjectTaskBoardItemAssignment
	query := s.db.Where("thread_id = ?", threadID)
	if cursorAssignmentOrder != nil && cursorID != nil {
		query = query.Where(
			"(assignment_order > ? OR (assignment_order = ? AND id > ?))",
			*cursorAssignmentOrder,
			*cursorAssignmentOrder,
			*cursorID,
		)
	}
	if err := query.
		Order("assignment_order ASC, id ASC").
		Limit(limit + 1).
		Find(&assignments).Error; err != nil {
		return nil, err
	}

	hasMore := len(assignments) > limit
	if hasMore {
		assignments = assignments[:limit]
	}

	nextCursor := ""
	if hasMore && len(assignments) > 0 {
		last := assignments[len(assignments)-1]
		nextCursor = encodeThreadAssignmentCursor(last.AssignmentOrder, last.ID)
	}

	return &ThreadAssignmentsResponse{
		Data:       assignments,
		Limit:      limit,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

func (s *Service) ListThreadEvents(
	threadID uint64,
	limit int,
	cursorCreatedAt *time.Time,
	cursorID *uint64,
) (*ThreadEventsResponse, error) {
	if limit <= 0 {
		limit = 40
	}
	if limit > 200 {
		limit = 200
	}

	var events []model.ThreadEvent
	query := s.db.Where("thread_id = ?", threadID)
	if cursorCreatedAt != nil && cursorID != nil {
		query = query.Where(
			"(created_at < ? OR (created_at = ? AND id < ?))",
			*cursorCreatedAt,
			*cursorCreatedAt,
			*cursorID,
		)
	}
	if err := query.
		Order("created_at DESC, id DESC").
		Limit(limit + 1).
		Find(&events).Error; err != nil {
		return nil, err
	}

	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}

	nextCursor := ""
	if hasMore && len(events) > 0 {
		last := events[len(events)-1]
		nextCursor = encodeThreadEventCursor(last.CreatedAt, last.ID)
	}

	return &ThreadEventsResponse{
		Data:       events,
		Limit:      limit,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

func encodeThreadTaskGraphCursor(version int, graphID uint64) string {
	raw := fmt.Sprintf("%d|%d", version, graphID)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func (s *Service) ListTaskGraphBundles(
	deploymentID, threadID uint64,
	limit int,
	cursorVersion *int,
	cursorID *uint64,
) (*ThreadTaskGraphsResponse, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}

	var graphs []model.ThreadTaskGraph
	query := s.db.Where("deployment_id = ? AND thread_id = ?", deploymentID, threadID)
	if cursorVersion != nil && cursorID != nil {
		query = query.Where("(version < ? OR (version = ? AND id < ?))", *cursorVersion, *cursorVersion, *cursorID)
	}

	if err := query.
		Order("version DESC, created_at DESC").
		Limit(limit + 1).
		Find(&graphs).Error; err != nil {
		return nil, err
	}
	if len(graphs) == 0 {
		return &ThreadTaskGraphsResponse{
			Data:    []ThreadTaskGraphBundle{},
			Limit:   limit,
			HasMore: false,
		}, nil
	}

	hasMore := len(graphs) > limit
	if hasMore {
		graphs = graphs[:limit]
	}

	graphIDs := make([]uint64, 0, len(graphs))
	for _, graph := range graphs {
		graphIDs = append(graphIDs, graph.ID)
	}

	var nodes []model.ThreadTaskNode
	if err := s.db.Where("graph_id IN ?", graphIDs).
		Order("graph_id DESC, created_at ASC").
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	var edges []model.ThreadTaskEdge
	if err := s.db.Where("graph_id IN ?", graphIDs).
		Order("graph_id DESC, created_at ASC").
		Find(&edges).Error; err != nil {
		return nil, err
	}

	summaryByGraphID, err := s.listTaskGraphSummaries(graphIDs)
	if err != nil {
		return nil, err
	}

	nodesByGraphID := make(map[uint64][]model.ThreadTaskNode, len(graphs))
	for _, node := range nodes {
		nodesByGraphID[node.GraphID] = append(nodesByGraphID[node.GraphID], node)
	}

	edgesByGraphID := make(map[uint64][]model.ThreadTaskEdge, len(graphs))
	for _, edge := range edges {
		edgesByGraphID[edge.GraphID] = append(edgesByGraphID[edge.GraphID], edge)
	}

	bundles := make([]ThreadTaskGraphBundle, 0, len(graphs))
	for _, graph := range graphs {
		graphNodes := nodesByGraphID[graph.ID]
		if graphNodes == nil {
			graphNodes = []model.ThreadTaskNode{}
		}
		graphEdges := edgesByGraphID[graph.ID]
		if graphEdges == nil {
			graphEdges = []model.ThreadTaskEdge{}
		}
		bundles = append(bundles, ThreadTaskGraphBundle{
			Graph:   graph,
			Nodes:   graphNodes,
			Edges:   graphEdges,
			Summary: summaryByGraphID[graph.ID],
		})
	}

	response := &ThreadTaskGraphsResponse{
		Data:    bundles,
		Limit:   limit,
		HasMore: hasMore,
	}
	if hasMore && len(graphs) > 0 {
		lastGraph := graphs[len(graphs)-1]
		response.NextCursor = encodeThreadTaskGraphCursor(lastGraph.Version, lastGraph.ID)
	}

	return response, nil
}

func (s *Service) listTaskGraphSummaries(graphIDs []uint64) (map[uint64]*ThreadTaskGraphSummary, error) {
	type summaryRow struct {
		GraphID         uint64  `gorm:"column:graph_id"`
		GraphStatus     string  `gorm:"column:graph_status"`
		TotalNodes      int64   `gorm:"column:total_nodes"`
		PendingNodes    int64   `gorm:"column:pending_nodes"`
		ReadyNodes      int64   `gorm:"column:ready_nodes"`
		InProgressNodes int64   `gorm:"column:in_progress_nodes"`
		CompletedNodes  int64   `gorm:"column:completed_nodes"`
		FailedNodes     int64   `gorm:"column:failed_nodes"`
		CancelledNodes  int64   `gorm:"column:cancelled_nodes"`
		ProgressPercent float64 `gorm:"column:progress_percent"`
	}

	rows := []summaryRow{}
	err := s.db.Raw(`
		SELECT
			g.id AS graph_id,
			g.status AS graph_status,
			COUNT(n.id) AS total_nodes,
			COUNT(*) FILTER (WHERE n.status = 'pending') AS pending_nodes,
			COUNT(*) FILTER (
				WHERE n.status = 'pending'
				AND NOT EXISTS (
					SELECT 1
					FROM thread_task_edges e
					JOIN thread_task_nodes dep ON dep.id = e.from_node_id AND dep.graph_id = e.graph_id
					WHERE e.graph_id = n.graph_id
					  AND e.to_node_id = n.id
					  AND dep.status != 'completed'
				)
			) AS ready_nodes,
			COUNT(*) FILTER (WHERE n.status = 'in_progress') AS in_progress_nodes,
			COUNT(*) FILTER (WHERE n.status = 'completed') AS completed_nodes,
			COUNT(*) FILTER (WHERE n.status = 'failed') AS failed_nodes,
			COUNT(*) FILTER (WHERE n.status = 'cancelled') AS cancelled_nodes,
			CASE
				WHEN COUNT(n.id) = 0 THEN 0
				ELSE ROUND((COUNT(*) FILTER (WHERE n.status = 'completed')::numeric / COUNT(n.id)::numeric) * 100, 2)
			END AS progress_percent
		FROM thread_task_graphs g
		LEFT JOIN thread_task_nodes n ON n.graph_id = g.id
		WHERE g.id IN ?
		GROUP BY g.id, g.status
	`, graphIDs).Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	summaryByGraphID := make(map[uint64]*ThreadTaskGraphSummary, len(rows))
	for _, row := range rows {
		summaryByGraphID[row.GraphID] = &ThreadTaskGraphSummary{
			GraphID:         strconv.FormatUint(row.GraphID, 10),
			GraphStatus:     row.GraphStatus,
			TotalNodes:      row.TotalNodes,
			PendingNodes:    row.PendingNodes,
			ReadyNodes:      row.ReadyNodes,
			InProgressNodes: row.InProgressNodes,
			CompletedNodes:  row.CompletedNodes,
			FailedNodes:     row.FailedNodes,
			CancelledNodes:  row.CancelledNodes,
			ProgressPercent: row.ProgressPercent,
		}
	}

	return summaryByGraphID, nil
}
