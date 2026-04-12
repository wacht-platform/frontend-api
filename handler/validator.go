package handler

import (
	"log"
	"strconv"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
)

var validate = validator.New()

type ValidationError struct {
	parseError       string
	validationErrors []string
}

func Validate[T any](c fiber.Ctx) (*T, *ValidationError) {
	p := new(T)
	validationError := &ValidationError{}

	if err := c.Bind().Body(p); err != nil {
		log.Println("parse error", err)
		validationError.parseError = err.Error()
	}

	if err := validate.Struct(p); err != nil {
		for _, e := range err.(validator.ValidationErrors) {
			validationError.validationErrors = append(
				validationError.validationErrors,
				e.Error(),
			)
		}
	}

	if validationError.parseError != "" ||
		len(validationError.validationErrors) > 0 {
		return nil, validationError
	}

	return p, nil
}

func SendResponse[T any](
	c fiber.Ctx,
	status int,
	data T,
	message string,
	errors []Error,
) error {
	session := GetSession(c)

	var safeSession any
	if session != nil {
		safeSession = map[string]any{
			"id":         strconv.FormatUint(session.ID, 10),
			"created_at": session.CreatedAt,
			"updated_at": session.UpdatedAt,
		}
	}

	return c.Status(status).JSON(fiber.Map{
		"status":  status,
		"message": message,
		"data":    data,
		"session": safeSession,
		"errors":  errors,
	})
}

func SendSuccess[T any](c fiber.Ctx, data T) error {
	return SendResponse(c, 200, data, "", nil)
}

func SendBadRequest(
	c fiber.Ctx,
	data any,
	message string,
	errors ...Error,
) error {
	return SendResponse(c, 400, data, message, errors)
}

func SendUnauthorized(
	c fiber.Ctx,
	data any,
	message string,
	errors ...Error,
) error {
	return SendResponse(c, 401, data, message, errors)
}

func SendForbidden(
	c fiber.Ctx,
	data any,
	message string,
	errors ...Error,
) error {
	return SendResponse(c, 403, data, message, errors)
}

func SendNotFound(
	c fiber.Ctx,
	data any,
	message string,
	errors ...Error,
) error {
	return SendResponse(c, 404, data, message, errors)
}

func SendInternalServerError(
	c fiber.Ctx,
	data any,
	message string,
	errors ...Error,
) error {
	return SendResponse[any](c, 500, nil, message, errors)
}

func SendTooManyRequests(
	c fiber.Ctx,
	data any,
	message string,
	errors ...Error,
) error {
	return SendResponse(c, 429, data, message, errors)
}
