package services

import (
	"context"
	"time"

	"github.com/ther0y/xeep-auth-service/internal/database"
	"github.com/ther0y/xeep-auth-service/internal/model"
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

		user, err := a.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, "user", user)

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

func (a *AuthInterceptor) authorize(ctx context.Context, method string) (user *model.User, err error) {
	accecibleRoles, ok := a.accessibleRoles[method]
	if !ok {
		// No roles required to access this method
		return nil, nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	values := md.Get("access_token")
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "access-token token is not provided")
	}

	accessToken := values[0]

	isInvalidated, err := AccessTokenManagerService.IsTokenInvalidated(accessToken)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to validate access token")
	}

	if isInvalidated {
		return nil, status.Error(codes.Unauthenticated, "access token is invalidated")
	}

	claims, err := AccessTokenManagerService.VerifyToken(accessToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	if claims.ExpiresAt < time.Now().Unix() {
		return nil, status.Error(codes.Unauthenticated, "access token is expired")
	}

	if claims.Issuer != "xeep-auth-service" {
		return nil, status.Error(codes.Unauthenticated, "access token is invalid")
	}

	if claims.Audience != "xeep-auth-service" {
		return nil, status.Error(codes.Unauthenticated, "access token is invalid")
	}

	if !a.hasRequiredRole(claims.Roles, accecibleRoles) {
		return nil, status.Error(codes.PermissionDenied, "user does not have required roles")
	}

	objectId, err := primitive.ObjectIDFromHex(claims.Subject)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get user")
	}

	err = database.UserCollection.FindOne(ctx, bson.M{"_id": objectId}).Decode(&user)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get user")
	}

	return user, nil
}
