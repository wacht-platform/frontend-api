package utils

import "fmt"

func CompleteEmailTemplate(
	subject string,
	body string,
) string {
	return fmt.Sprintf(
		`<html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>%s</title></head><body>%s</body></html>`,
		subject,
		body,
	)
}
