package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/database/repositories"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"github.com/ther0y/xeep-auth-service/internal/utils"
	"github.com/ther0y/xeep-auth-service/internal/validator"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

func (s *Service) Register(ctx context.Context, req *auther.RegisterRequest) (*auther.RegisterResponse, error) {
	violations := validateRegisterRequest(req)
	if violations != nil {
		return nil, invalidArgumentError(violations)
	}

	var userRepo = repositories.NewUserRepository()

	normalizedPhone := utils.NormalizePhone(req.Phone)
	passwordHash, salt := utils.HashPassword(req.Password)

	fmt.Println("salt: ", salt)

	newUser := &model.User{
		ID:        primitive.NewObjectID(),
		Username:  req.Username,
		Email:     req.Email,
		Phone:     normalizedPhone,
		Password:  passwordHash,
		Salt:      salt,
		CreatedAt: time.Now().Unix(),
		UpdatedAt: time.Now().Unix(),
	}

	u, err := userRepo.InsertUser(context.Background(), newUser)
	if err != nil {
		return nil, err
	}

	tokens, err := u.GenerateTokens()
	if err != nil {
		return nil, err
	}

	return &auther.RegisterResponse{
		AuthenticationData: &auther.AuthenticationData{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			Id:           newUser.ID.Hex(),
		},
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
