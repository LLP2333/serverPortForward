package app

import (
	"errors"
	"fmt"
	"net/http"
)

type AppError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Details    string `json:"details,omitempty"`
	HTTPStatus int    `json:"-"`
}

func (e *AppError) Error() string {
	if e.Details == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Message, e.Details)
}

func appError(code, message, details string, status int) *AppError {
	if status == 0 {
		status = http.StatusInternalServerError
	}
	return &AppError{Code: code, Message: message, Details: sanitizeDetail(details), HTTPStatus: status}
}

func asAppError(err error) *AppError {
	var target *AppError
	if errors.As(err, &target) {
		return target
	}
	return appError("INTERNAL_ERROR", "操作失败", err.Error(), http.StatusInternalServerError)
}
