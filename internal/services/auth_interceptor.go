package services

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthInterceptor struct {
	accessibleRoles map[string][]string
}

func NewAuthInterceptor(accecibleRoles map[string][]string) *AuthInterceptor {
	return &AuthInterceptor{accecibleRoles}
}

func (a *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {

		if err := a.authorize(ctx, info.FullMethod); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func (a *AuthInterceptor) hasRequiredRole(roles []string, requiredRoles []string) bool {
	for _, requiredRole := range requiredRoles {
		for _, role := range roles {
			if role == requiredRole {
				return true
			}
		}
	}
	return false
}

func (a *AuthInterceptor) authorize(ctx context.Context, method string) error {
	accecibleRoles, ok := a.accessibleRoles[method]
	if !ok {
		// No roles required to access this method
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, "authorization token is not provided")
	}

	accesstoken := values[0]

	claims, err := AccessTokenManagerService.VerifyToken(accesstoken)
	if err != nil {
		return status.Error(codes.Unauthenticated, "access token is invalid")
	}

	if claims.ExpiresAt < time.Now().Unix() {
		return status.Error(codes.Unauthenticated, "access token is expired")
	}

	if claims.Issuer != "xeep-auth-service" {
		return status.Error(codes.Unauthenticated, "access token is invalid")
	}

	if claims.Audience != "xeep-auth-service" {
		return status.Error(codes.Unauthenticated, "access token is invalid")
	}

	if !a.hasRequiredRole(claims.Roles, accecibleRoles) {
		return status.Error(codes.PermissionDenied, "user does not have required roles")
	}

	ctx = context.WithValue(ctx, "user", claims)

	return nil
}
