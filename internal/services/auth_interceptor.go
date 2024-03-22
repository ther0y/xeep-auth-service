package services

import (
	"context"
	"fmt"
	"github.com/ther0y/xeep-auth-service/internal/utils"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthInterceptor struct {
	accessibleRoles map[string][]string
}

func NewAuthInterceptor(accessibleRoles map[string][]string) *AuthInterceptor {
	return &AuthInterceptor{accessibleRoles}
}

func (a *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {

		err := a.authorize(&ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func (a *AuthInterceptor) authorize(ctx *context.Context, method string) (err error) {
	accessibleRoles, ok := a.accessibleRoles[method]
	if !ok {
		// No roles required to access this method
		return nil
	}

	accessToken, err := extractAccessToken(*ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	claims, err := validateAccessToken(accessToken)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	if err := checkSessionValidity(claims.SessionID); err != nil {
		return err
	}

	if err := checkTokenClaims(claims); err != nil {
		return err
	}

	if !hasRequiredRole(claims.Roles, accessibleRoles) {
		return status.Error(codes.PermissionDenied, "user does not have required roles")
	}

	if err := setUserAndSessionInContext(ctx, &claims.SessionClaims); err != nil {
		return err
	}

	return nil
}

func extractAccessToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("metadata is not provided")
	}

	values := md.Get("access_token")
	if len(values) == 0 {
		return "", fmt.Errorf("access-token token is not provided")
	}

	return values[0], nil
}

func validateAccessToken(accessToken string) (*UserClaims, error) {
	return AccessTokenManagerService.GetClaims(accessToken)
}

func hasRequiredRole(roles []string, requiredRoles []string) bool {
	for _, requiredRole := range requiredRoles {
		for _, role := range roles {
			if role == requiredRole {
				return true
			}
		}
	}
	return false
}

func checkSessionValidity(sessionID string) error {
	isSessionInvalidated, err := IsSessionInvalidated(sessionID)
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to check if session is invalidated: %w", err).Error())
	}

	if isSessionInvalidated {
		return status.Error(codes.Unauthenticated, "session is invalidated")
	}

	return nil
}

func checkTokenClaims(claims *UserClaims) error {
	if claims.ExpiresAt < time.Now().Unix() {
		return status.Error(codes.Unauthenticated, "access token is expired")
	}

	allowedIssuer, err := utils.GetEnv("TOKEN_ISSUER")
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to get access token issuer from env: %w", err).Error())
	}

	if claims.Issuer != allowedIssuer {
		return status.Error(codes.Unauthenticated, "access token is invalid")
	}

	allowedAudience, err := utils.GetEnv("TOKEN_AUDIENCE")
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to get access token audience from env: %w", err).Error())
	}

	if claims.Audience != allowedAudience {
		return status.Error(codes.Unauthenticated, "access token is invalid")
	}

	return nil
}
