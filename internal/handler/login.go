package handler

import (
	"context"

	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/database/repositories"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

func (s *Service) Login(ctx context.Context, req *auther.LoginRequest) (*auther.LoginResponse, error) {
	violations := validateLoginRequest(req)
	if violations != nil {
		return nil, invalidArgumentError(violations)
	}

	userRepo := repositories.NewUserRepository()

	user, err := userRepo.FindByIdentifier(ctx, req.Identifier)
	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			return nil, unauthenticatedError("Invalid credentials")
		}

		return nil, err
	}

	if user == nil {
		return nil, unauthenticatedError("Invalid credentials")
	}

	match, err := user.ComparePassword(req.Password)
	if err != nil {
		return nil, internalError(err.Error())
	}

	if !match {
		return nil, unauthenticatedError("Invalid credentials")
	}

	tokens, err := user.GenerateTokens()
	if err != nil {
		return nil, err
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
