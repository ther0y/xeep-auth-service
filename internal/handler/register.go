package handler

import (
	"context"
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
		return nil, invalidArgumentError(violations)
	}

	newUser := model.NewUser()
	if exists, err := newUser.IsIdentifierExists(ctx, req.Username); err != nil {
		return nil, internalError(err.Error())
	} else if exists {
		return nil, alreadyExistsError("Identifier")
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
			return nil, internalError("Failed to create user")
		}

		return nil, internalError(err.Error())
	}

	session, err := newUser.SaveSession(":", "", "")
	if err != nil {
		return nil, internalError(err.Error())
	}

	tokens, err := services.GenerateUserTokens(newUser, session.ID.Hex())
	if err != nil {
		return nil, internalError(err.Error())
	}

	return &auther.AuthenticationData{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Id:           newUser.ID.Hex(),
	}, nil
}

func validateRegisterRequest(req *auther.RegisterRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if err := validator.ValidateUsername(req.GetUsername()); err != nil {
		violations = append(violations, fieldViolation("username", err))
	}

	if err := validator.ValidateEmail(req.GetEmail()); err != nil {
		violations = append(violations, fieldViolation("email", err))
	}

	if err := validator.ValidatePhone(req.GetPhone()); err != nil {
		violations = append(violations, fieldViolation("phone", err))
	}

	if err := validator.ValidatePassword(req.GetPassword()); err != nil {
		violations = append(violations, fieldViolation("password", err))
	}

	return violations
}
