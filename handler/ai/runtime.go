package ai

import (
	"bufio"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/nats-io/nats.go"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/service"
)

func containsInt64(values []int64, target int64) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sessionHasAgent(agentSession *model.AgentSession, agentID uint64) bool {
	if agentID > math.MaxInt64 {
		return false
	}
	return containsInt64(agentSession.AgentIDs, int64(agentID))
}

func (h *Handler) GetSession(c fiber.Ctx) error {
	_, _, err := h.getActorScope(c)
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "No active agent session")
	}

	deployment := handler.GetDeployment(c)
	session := handler.GetSession(c)
	if session == nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Session required")
	}
	response, err := h.service.GetHydratedAgentSessionResponse(session.ID, deployment.ID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to fetch agent session")
	}

	return handler.SendSuccess(c, response)
}

func (h *Handler) GetThreadMessages(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}

	threadIDStr := c.Params("thread_id")
	threadID, err := strconv.ParseUint(threadIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid thread ID")
	}

	limit := fiber.Query[int](c, "limit", 50)
	if limit > 100 {
		limit = 100
	}

	beforeID := c.Query("before_id")
	afterID := c.Query("after_id")
	boardItemID, _ := strconv.ParseUint(c.Query("board_item_id"), 10, 64)

	deployment := handler.GetDeployment(c)
	messages, hasMore, err := h.service.GetThreadMessages(
		deployment.ID,
		actorID,
		threadID,
		limit,
		beforeID,
		afterID,
		boardItemID,
	)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to fetch thread messages")
	}

	return handler.SendSuccess(c, ListMessagesResponse{
		Data:    messages,
		HasMore: hasMore,
	})
}

func (h *Handler) Stream(c fiber.Ctx) error {
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
		return handler.SendNotFound(c, nil, "Thread not found or access denied")
	}

	natsService := service.GetNATS()
	subject := fmt.Sprintf("agent_execution_stream.thread:%d", threadID)
	msgCh := make(chan *nats.Msg, 128)

	sub, err := natsService.Conn().ChanSubscribe(subject, msgCh)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to subscribe to agent stream")
	}

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	ctx := c.Context()

	c.RequestCtx().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer func() {
			_ = sub.Unsubscribe()
			close(msgCh)
		}()

		_, _ = fmt.Fprintf(w, "event: connected\ndata: {\"thread_id\":\"%d\"}\n\n", threadID)
		_ = w.Flush()

		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-msgCh:
				if !ok {
					return
				}

				eventType := "message"
				if msg.Header != nil {
					if headerValue := msg.Header.Get("message_type"); headerValue != "" {
						eventType = headerValue
					}
				}

				_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, string(msg.Data))
				if err := w.Flush(); err != nil {
					return
				}
			case <-time.After(10 * time.Second):
				_, _ = fmt.Fprint(w, ": keep-alive\n\n")
				if err := w.Flush(); err != nil {
					return
				}
			}
		}
	})

	return nil
}
