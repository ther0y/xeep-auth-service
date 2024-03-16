package handler

import (
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func fieldViolation(field string, err error) *errdetails.BadRequest_FieldViolation {
	return &errdetails.BadRequest_FieldViolation{Field: field, Description: err.Error()}
}

func invalidArgumentError(violations []*errdetails.BadRequest_FieldViolation) error {
	badRequest := &errdetails.BadRequest{FieldViolations: violations}

	statusInvalid := status.New(codes.Internal, "invalid parameters")

	statusDetails, err := statusInvalid.WithDetails(badRequest)

	fmt.Println(statusDetails.Err().Error())

	if err != nil {
		return statusInvalid.Err()
	}

	return statusDetails.Err()
}

func unauthenticatedError(msg string) error {
	return status.Error(codes.Unauthenticated, msg)
}

func internalError(msg string) error {
	return status.Error(codes.Internal, msg)
}

func alreadyExistsError(field string) error {
	return status.Error(codes.AlreadyExists, fmt.Sprintf("%s already exists", field))
}
