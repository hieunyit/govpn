package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// Domain errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrGroupNotFound      = errors.New("group not found")
	ErrGroupAlreadyExists = errors.New("group already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrBadRequest         = errors.New("bad request")
	ErrInternalServer     = errors.New("internal server error")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrLDAPConnection     = errors.New("LDAP connection failed")
	ErrLDAPAuthentication = errors.New("LDAP authentication failed")
	ErrXMLRPCCall         = errors.New("XML-RPC call failed")
	ErrInvalidInput       = errors.New("invalid input")
	ErrValidationFailed   = errors.New("validation failed")
)

// AppError represents application error with HTTP status code
type AppError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"status"`
	Err     error  `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// NewAppError creates a new application error
func NewAppError(code, message string, status int, err error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Status:  status,
		Err:     err,
	}
}

// Common error constructors
func BadRequest(message string, err error) *AppError {
	return NewAppError("BAD_REQUEST", message, http.StatusBadRequest, err)
}

func Unauthorized(message string, err error) *AppError {
	return NewAppError("UNAUTHORIZED", message, http.StatusUnauthorized, err)
}

func Forbidden(message string, err error) *AppError {
	return NewAppError("FORBIDDEN", message, http.StatusForbidden, err)
}

func NotFound(message string, err error) *AppError {
	return NewAppError("NOT_FOUND", message, http.StatusNotFound, err)
}

func Conflict(message string, err error) *AppError {
	return NewAppError("CONFLICT", message, http.StatusConflict, err)
}

func InternalServerError(message string, err error) *AppError {
	return NewAppError("INTERNAL_SERVER_ERROR", message, http.StatusInternalServerError, err)
}
