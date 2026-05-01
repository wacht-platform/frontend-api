package ai

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type AnswerKind struct {
	Kind          string   `json:"kind"`
	Placeholder   *string  `json:"placeholder,omitempty"`
	MaxLength     *uint32  `json:"max_length,omitempty"`
	Choices       []Choice `json:"choices,omitempty"`
	AllowOther    *bool    `json:"allow_other,omitempty"`
	MinSelected   *uint32  `json:"min_selected,omitempty"`
	MaxSelected   *uint32  `json:"max_selected,omitempty"`
	Min           *float64 `json:"min,omitempty"`
	Max           *float64 `json:"max,omitempty"`
	MinDate       *string  `json:"-"`
	MaxDate       *string  `json:"-"`
	Unit          *string  `json:"unit,omitempty"`
	ConfirmLabel  *string  `json:"confirm_label,omitempty"`
	CancelLabel   *string  `json:"cancel_label,omitempty"`
}

type Choice struct {
	Value       string  `json:"value"`
	Label       string  `json:"label"`
	Description *string `json:"description,omitempty"`
}

type Question struct {
	ID         string          `json:"id"`
	Text       string          `json:"text"`
	AnswerKind json.RawMessage `json:"answer_kind"`
}

type PendingQuestion struct {
	Questions             []Question `json:"questions"`
	Context               *string    `json:"context,omitempty"`
	AskedAt               time.Time  `json:"asked_at"`
	AskedByThreadID       string     `json:"asked_by_thread_id"`
	AskedByAssignmentID   *string    `json:"asked_by_assignment_id,omitempty"`
}

type AnswerValue struct {
	Kind     string   `json:"kind"`
	Value    *string  `json:"value,omitempty"`
	Values   []string `json:"values,omitempty"`
	Bool     *bool    `json:"value_bool,omitempty"`
	Number   *float64 `json:"value_number,omitempty"`
	Accepted *bool    `json:"accepted,omitempty"`
}

type rawAnswerValue struct {
	Kind     string          `json:"kind"`
	Value    json.RawMessage `json:"value,omitempty"`
	Values   []string        `json:"values,omitempty"`
	Accepted *bool           `json:"accepted,omitempty"`
}

type QuestionAnswer struct {
	QuestionID string          `json:"question_id"`
	Value      json.RawMessage `json:"value"`
}

type AnswerSubmission struct {
	Answers []QuestionAnswer `json:"answers"`
}

type rawAnswerKind struct {
	Kind         string   `json:"kind"`
	MaxLength    *uint32  `json:"max_length,omitempty"`
	Choices      []Choice `json:"choices,omitempty"`
	AllowOther   *bool    `json:"allow_other,omitempty"`
	MinSelected  *uint32  `json:"min_selected,omitempty"`
	MaxSelected  *uint32  `json:"max_selected,omitempty"`
	Min          *float64 `json:"min,omitempty"`
	Max          *float64 `json:"max,omitempty"`
	MinDate      *string  `json:"min_date,omitempty"`
	MaxDate      *string  `json:"max_date,omitempty"`
	ConfirmLabel *string  `json:"confirm_label,omitempty"`
	CancelLabel  *string  `json:"cancel_label,omitempty"`
}

func validateAnswers(pending *PendingQuestion, submission *AnswerSubmission) error {
	if len(submission.Answers) != len(pending.Questions) {
		return fmt.Errorf("expected %d answers, got %d", len(pending.Questions), len(submission.Answers))
	}
	seen := map[string]bool{}
	byID := map[string]Question{}
	for _, q := range pending.Questions {
		byID[q.ID] = q
	}
	for _, ans := range submission.Answers {
		if seen[ans.QuestionID] {
			return fmt.Errorf("duplicate answer for question_id '%s'", ans.QuestionID)
		}
		seen[ans.QuestionID] = true
		question, ok := byID[ans.QuestionID]
		if !ok {
			return fmt.Errorf("unknown question_id '%s'", ans.QuestionID)
		}
		if err := validateAnswerForQuestion(&question, ans.Value); err != nil {
			return fmt.Errorf("question %s: %w", ans.QuestionID, err)
		}
	}
	return nil
}

func validateAnswerForQuestion(question *Question, value json.RawMessage) error {
	var akRaw rawAnswerKind
	if err := json.Unmarshal(question.AnswerKind, &akRaw); err != nil {
		return fmt.Errorf("malformed answer_kind: %w", err)
	}
	var vRaw rawAnswerValue
	if err := json.Unmarshal(value, &vRaw); err != nil {
		return fmt.Errorf("malformed answer value: %w", err)
	}

	if akRaw.Kind != vRaw.Kind {
		return fmt.Errorf("answer kind '%s' does not match question kind '%s'", vRaw.Kind, akRaw.Kind)
	}

	switch akRaw.Kind {
	case "free_text":
		var v string
		if err := json.Unmarshal(vRaw.Value, &v); err != nil {
			return fmt.Errorf("free_text answer must be a string")
		}
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("free_text answer must be non-empty")
		}
		if akRaw.MaxLength != nil && uint32(len([]rune(v))) > *akRaw.MaxLength {
			return fmt.Errorf("free_text answer exceeds max_length %d", *akRaw.MaxLength)
		}
	case "single_choice":
		var v string
		if err := json.Unmarshal(vRaw.Value, &v); err != nil {
			return fmt.Errorf("single_choice answer must be a string")
		}
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("single_choice answer must be non-empty")
		}
		known := false
		for _, c := range akRaw.Choices {
			if c.Value == v {
				known = true
				break
			}
		}
		if !known && (akRaw.AllowOther == nil || !*akRaw.AllowOther) {
			return fmt.Errorf("'%s' is not a valid choice", v)
		}
	case "multi_choice":
		count := uint32(len(vRaw.Values))
		if akRaw.MinSelected != nil && count < *akRaw.MinSelected {
			return fmt.Errorf("multi_choice requires at least %d selections", *akRaw.MinSelected)
		}
		if akRaw.MaxSelected != nil && count > *akRaw.MaxSelected {
			return fmt.Errorf("multi_choice allows at most %d selections", *akRaw.MaxSelected)
		}
		seen := map[string]bool{}
		valid := map[string]bool{}
		for _, c := range akRaw.Choices {
			valid[c.Value] = true
		}
		for _, v := range vRaw.Values {
			if seen[v] {
				return fmt.Errorf("duplicate selection '%s'", v)
			}
			seen[v] = true
			if !valid[v] {
				return fmt.Errorf("'%s' is not a valid choice", v)
			}
		}
	case "yes_no":
		var v bool
		if err := json.Unmarshal(vRaw.Value, &v); err != nil {
			return fmt.Errorf("yes_no answer must be a boolean")
		}
	case "number":
		var v float64
		if err := json.Unmarshal(vRaw.Value, &v); err != nil {
			return fmt.Errorf("number answer must be a number")
		}
		if akRaw.Min != nil && v < *akRaw.Min {
			return fmt.Errorf("number %g below min %g", v, *akRaw.Min)
		}
		if akRaw.Max != nil && v > *akRaw.Max {
			return fmt.Errorf("number %g above max %g", v, *akRaw.Max)
		}
	case "date":
		var v string
		if err := json.Unmarshal(vRaw.Value, &v); err != nil {
			return fmt.Errorf("date answer must be yyyy-mm-dd string")
		}
		parsed, err := time.Parse("2006-01-02", v)
		if err != nil {
			return fmt.Errorf("date '%s' must be ISO yyyy-mm-dd", v)
		}
		if akRaw.MinDate != nil {
			minBound, err := time.Parse("2006-01-02", *akRaw.MinDate)
			if err != nil {
				return fmt.Errorf("min_date '%s' invalid", *akRaw.MinDate)
			}
			if parsed.Before(minBound) {
				return fmt.Errorf("date %s before min_date %s", v, *akRaw.MinDate)
			}
		}
		if akRaw.MaxDate != nil {
			maxBound, err := time.Parse("2006-01-02", *akRaw.MaxDate)
			if err != nil {
				return fmt.Errorf("max_date '%s' invalid", *akRaw.MaxDate)
			}
			if parsed.After(maxBound) {
				return fmt.Errorf("date %s after max_date %s", v, *akRaw.MaxDate)
			}
		}
	case "confirm":
		if vRaw.Accepted == nil {
			return fmt.Errorf("confirm answer must include 'accepted' boolean")
		}
	default:
		return fmt.Errorf("unknown answer kind '%s'", akRaw.Kind)
	}
	return nil
}
