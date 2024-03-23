package errors

import (
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func FieldViolation(field string, err error) *errdetails.BadRequest_FieldViolation {
	return &errdetails.BadRequest_FieldViolation{Field: field, Description: err.Error()}
}

func InvalidArgumentError(violations []*errdetails.BadRequest_FieldViolation) error {
	badRequest := &errdetails.BadRequest{FieldViolations: violations}

	statusInvalid := status.New(codes.Internal, "invalid parameters")

	statusDetails, err := statusInvalid.WithDetails(badRequest)
	if err != nil {
		return statusInvalid.Err()
	}

	return statusDetails.Err()
}

func UnauthenticatedError(msg string) error {
	return status.Error(codes.Unauthenticated, msg)
}

func InternalError(msg string, err error) error {
	return status.Error(codes.Internal, fmt.Errorf("%s: %w", msg, err).Error())
}

func AlreadyExistsError(field string) error {
	return status.Error(codes.AlreadyExists, fmt.Sprintf("%s already exists", field))
}

func RequiredField() error {
	return status.Error(codes.InvalidArgument, "required field")
}
