package handler

import (
	"context"
	"github.com/ther0y/xeep-auth-service/internal/errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"

	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"github.com/ther0y/xeep-auth-service/internal/services"
	"github.com/ther0y/xeep-auth-service/internal/utils"
	"github.com/ther0y/xeep-auth-service/internal/validator"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

func (s *Service) Register(ctx context.Context, req *auther.RegisterRequest) (*auther.AuthenticationData, error) {
	violations := validateRegisterRequest(req)
	if violations != nil {
		return nil, errors.InvalidArgumentError(violations)
	}

	newUser := model.NewUser()
	if exists, err := newUser.IsIdentifierExists(ctx, req.Username); err != nil {
		return nil, errors.InternalError("Failed to check if the username exists", err)
	} else if exists {
		return nil, errors.AlreadyExistsError("Identifier")
	}

	normalizedPhone := utils.NormalizePhone(req.Phone)
	passwordHash, salt := utils.HashPassword(req.Password)

	newUser = &model.User{
		ID:        primitive.NewObjectID(),
		Username:  req.Username,
		Email:     req.Email,
		Phone:     normalizedPhone,
		Password:  passwordHash,
		Salt:      salt,
		CreatedAt: time.Now().Unix(),
		UpdatedAt: time.Now().Unix(),
	}

	err := newUser.Save()
	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			return nil, errors.InternalError("Failed to create user", err)
		}

		return nil, errors.InternalError("Failed to create user", err)
	}

	session, err := newUser.SaveSession(":", "", "")
	if err != nil {
		return nil, errors.InternalError("Failed to save the session", err)
	}

	tokens, err := services.GenerateUserTokens(newUser, session.ID.Hex())
	if err != nil {
		return nil, errors.InternalError("Failed to generate the tokens", err)
	}

	return &auther.AuthenticationData{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Id:           newUser.ID.Hex(),
	}, nil
}

func validateRegisterRequest(req *auther.RegisterRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if err := validator.ValidateUsername(req.GetUsername()); err != nil {
		violations = append(violations, errors.FieldViolation("username", err))
	}

	if err := validator.ValidateEmail(req.GetEmail()); err != nil {
		violations = append(violations, errors.FieldViolation("email", err))
	}

	if err := validator.ValidatePhone(req.GetPhone()); err != nil {
		violations = append(violations, errors.FieldViolation("phone", err))
	}

	if err := validator.ValidatePassword(req.GetPassword()); err != nil {
		violations = append(violations, errors.FieldViolation("password", err))
	}

	return violations
}
