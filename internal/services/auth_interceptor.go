package services

import (
	"context"
	"fmt"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"github.com/ther0y/xeep-auth-service/internal/utils"
	"time"

	"github.com/ther0y/xeep-auth-service/internal/database"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

		err := a.authorize(&ctx, info.FullMethod)
		if err != nil {
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

func (a *AuthInterceptor) authorize(ctx *context.Context, method string) (err error) {
	accessibleRoles, ok := a.accessibleRoles[method]
	if !ok {
		// No roles required to access this method
		return nil
	}

	md, ok := metadata.FromIncomingContext(*ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	values := md.Get("access_token")
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, "access-token token is not provided")
	}

	accessToken := values[0]

	claims, err := AccessTokenManagerService.VerifyToken(accessToken)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	isSessionInvalidated, err := IsSessionInvalidated(claims.SessionID)
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to check if session is invalidated: %w", err).Error())
	}

	if isSessionInvalidated {
		return status.Error(codes.Unauthenticated, "session is invalidated")
	}

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

	if !a.hasRequiredRole(claims.Roles, accessibleRoles) {
		return status.Error(codes.PermissionDenied, "user does not have required roles")
	}

	userObjectID, err := primitive.ObjectIDFromHex(claims.Subject)
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to convert user id to object id: %w", err).Error())
	}

	user := &model.User{}
	err = database.UserCollection.FindOne(*ctx, bson.M{"_id": userObjectID}).Decode(&user)
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to get user from database: %w", err).Error())
	}

	user.SessionID = claims.SessionID
	*ctx = context.WithValue(*ctx, "user", user)
	return nil
}
