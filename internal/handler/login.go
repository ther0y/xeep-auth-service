package handler

import (
	"context"
	"github.com/ther0y/xeep-auth-service/internal/errors"

	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"github.com/ther0y/xeep-auth-service/internal/services"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

func (s *Service) Login(ctx context.Context, req *auther.LoginRequest) (*auther.AuthenticationData, error) {
	violations := validateLoginRequest(req)
	if violations != nil {
		return nil, errors.InvalidArgumentError(violations)
	}

	user := model.User{}
	err := user.FindByIdentifier(ctx, req.Identifier)
	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			return nil, errors.UnauthenticatedError("Invalid credentials")
		}

		return nil, err
	}

	if user.ID.IsZero() {
		return nil, errors.UnauthenticatedError("Invalid credentials")
	}

	match, err := user.ComparePassword(req.Password)
	if err != nil {
		return nil, errors.InternalError("failed to compare the password", err)
	}

	if !match {
		return nil, errors.UnauthenticatedError("Invalid credentials")
	}

	session, err := user.SaveSession(":", "", "")
	if err != nil {
		return nil, errors.InternalError("failed to save the session", err)
	}

	tokens, err := services.GenerateUserTokens(&user, session.ID.Hex())
	if err != nil {
		return nil, errors.InternalError("failed to generate the tokens", err)
	}

	return &auther.AuthenticationData{
		Id:           user.ID.Hex(),
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
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
