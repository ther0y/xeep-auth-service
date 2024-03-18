package handler

import (
	"context"

	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"github.com/ther0y/xeep-auth-service/internal/services"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

func (s *Service) Login(ctx context.Context, req *auther.LoginRequest) (*auther.LoginResponse, error) {
	violations := validateLoginRequest(req)
	if violations != nil {
		return nil, invalidArgumentError(violations)
	}

	user := model.User{}
	err := user.FindByIdentifier(ctx, req.Identifier)
	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			return nil, unauthenticatedError("Invalid credentials")
		}

		return nil, err
	}

	if user.ID.IsZero() {
		return nil, unauthenticatedError("Invalid credentials")
	}

	match, err := user.ComparePassword(req.Password)
	if err != nil {
		return nil, internalError(err.Error())
	}

	if !match {
		return nil, unauthenticatedError("Invalid credentials")
	}

	tokens, err := services.GenerateUserTokens(&user)
	if err != nil {
		return nil, internalError(err.Error())
	}

	return &auther.LoginResponse{
		AuthenticationData: &auther.AuthenticationData{
			Id:           user.ID.Hex(),
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
		},
	}, nil
}

func validateLoginRequest(req *auther.LoginRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if req.Identifier == "" {
		violations = append(violations, &errdetails.BadRequest_FieldViolation{
			Field:       "identifier",
			Description: "Identifier is required",
		})
	}

	if req.Password == "" {
		violations = append(violations, &errdetails.BadRequest_FieldViolation{
			Field:       "password",
			Description: "Password is required",
		})
	}

	return violations
}
