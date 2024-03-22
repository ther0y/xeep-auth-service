package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/database"
	"github.com/ther0y/xeep-auth-service/internal/errors"
	"github.com/ther0y/xeep-auth-service/internal/services"
	"github.com/ther0y/xeep-auth-service/internal/utils"
	"github.com/ther0y/xeep-auth-service/internal/validator"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"math/rand"
	"strconv"
)

func (s *Service) SendSmsOTP(ctx context.Context, req *auther.SendSmSOTPRequest) (*auther.SuccessResponse, error) {
	violations := validateOtpRequest(req)
	if violations != nil {
		return nil, errors.InvalidArgumentError(violations)
	}

	smsService := services.NewSmsService()

	normalizedPhone := utils.NormalizePhone(req.GetPhone())
	otpCode := generateOtp()
	hashedOtpCode := hashOtp(otpCode)

	if err := smsService.SendSmsOtp(normalizedPhone, otpCode); err != nil {
		return nil, err
	}

	if err := database.StoreHashedSmsOtp(normalizedPhone, hashedOtpCode); err != nil {
		return nil, errors.InternalError("Failed to save the OTP", err)
	}

	return &auther.SuccessResponse{
		Success: true,
	}, nil
}

func validateOtpRequest(req *auther.SendSmSOTPRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if req.Phone == "" {
		violations = append(violations, errors.FieldViolation("phone", fmt.Errorf("phone is required")))
	}

	if err := validator.ValidatePhone(req.GetPhone()); err != nil {
		violations = append(violations, errors.FieldViolation("phone", err))
	}

	return violations
}

func generateOtp() string {
	return strconv.Itoa(rand.Intn(999999-100000) + 100000)
}

func hashOtp(otpCode string) string {
	hash := sha256.Sum256([]byte(otpCode))
	hashedToken := base64.StdEncoding.EncodeToString(hash[:])

	return hashedToken
}
