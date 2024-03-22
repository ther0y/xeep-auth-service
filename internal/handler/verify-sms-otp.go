package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/database"
	"github.com/ther0y/xeep-auth-service/internal/errors"
	"github.com/ther0y/xeep-auth-service/internal/utils"
	"github.com/ther0y/xeep-auth-service/internal/validator"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

func (s *Service) VerifySmsOTP(ctx context.Context, req *auther.VerifySmsOtpRequest) (*auther.VerifySmsOtpResponse, error) {
	violations := validateVerifySmsOtpRequest(req)
	if violations != nil {
		return nil, errors.InvalidArgumentError(violations)
	}

	normalizedPhone := utils.NormalizePhone(req.GetPhone())
	hashedSentOtp := hashOtp(req.Otp)

	ok, err := database.CompareHashedSmsOtp(normalizedPhone, hashedSentOtp)
	if err != nil {
		return nil, err
	}

	if !ok {
		return &auther.VerifySmsOtpResponse{
			Success: false,
		}, nil
	}

	if err := database.DeleteHashedSmsOtp(normalizedPhone); err != nil {
		return nil, errors.InternalError("Failed to delete the OTP", err)
	}

	validationKey, err := generateOtpValidationKey()
	if err != nil {
		return nil, errors.InternalError("Failed to generate the OTP validation key", err)
	}

	if err := database.StoreOtpValidationKey(normalizedPhone, validationKey); err != nil {
		return nil, errors.InternalError("Failed to save the OTP validation key", err)
	}

	return &auther.VerifySmsOtpResponse{
		Success:       true,
		ValidationKey: validationKey,
	}, nil
}

func generateOtpValidationKey() (string, error) {
	// generate a random 24 character string using crypto/rand
	b := make([]byte, 24)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

func validateVerifySmsOtpRequest(req *auther.VerifySmsOtpRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if req.Phone == "" {
		violations = append(violations, errors.FieldViolation("phone", fmt.Errorf("phone is required")))
	}

	if err := validator.ValidatePhone(req.GetPhone()); err != nil {
		violations = append(violations, errors.FieldViolation("phone", err))
	}

	if req.Otp == "" {
		violations = append(violations, errors.FieldViolation("otp", fmt.Errorf("otp is required")))
	}

	if err := validator.ValidateOtp(req.GetOtp()); err != nil {
		violations = append(violations, errors.FieldViolation("otp", err))
	}

	return violations
}
