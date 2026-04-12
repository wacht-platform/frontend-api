package ai

import (
	"bytes"
	"embed"
	"fmt"
	"strings"
	"text/template"
)

//go:embed prompts/default-thread-*.md.tmpl
var defaultThreadInstructionFS embed.FS

var defaultThreadInstructionTemplates = template.Must(
	template.New("default-thread-instructions").
		Funcs(template.FuncMap{
			"projectBrief": func(value *string) string {
				if value == nil {
					return "No explicit project brief was provided."
				}
				trimmed := strings.TrimSpace(*value)
				if trimmed == "" {
					return "No explicit project brief was provided."
				}
				return trimmed
			},
		}).
		ParseFS(
			defaultThreadInstructionFS,
			"prompts/default-thread-coordinator.md.tmpl",
			"prompts/default-thread-review.md.tmpl",
		),
)

type defaultThreadInstructionTemplateData struct {
	ProjectName  string
	ProjectBrief *string
}

func buildProjectThreadSystemInstructions(
	projectName string,
	projectDescription *string,
	threadKind string,
) (string, error) {
	var templateName string
	switch threadKind {
	case "coordinator":
		templateName = "default-thread-coordinator.md.tmpl"
	case "review":
		templateName = "default-thread-review.md.tmpl"
	default:
		return "", fmt.Errorf("unsupported default project thread kind %q", threadKind)
	}

	var buffer bytes.Buffer
	if err := defaultThreadInstructionTemplates.ExecuteTemplate(
		&buffer,
		templateName,
		defaultThreadInstructionTemplateData{
			ProjectName:  projectName,
			ProjectBrief: projectDescription,
		},
	); err != nil {
		return "", fmt.Errorf("failed to render %s instructions: %w", threadKind, err)
	}

	return strings.TrimSpace(buffer.String()), nil
}
