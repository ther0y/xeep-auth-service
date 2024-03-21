package services

import (
	"context"
	"github.com/ther0y/xeep-auth-service/internal/model"
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
	if err != nil || isSessionInvalidated {
		return status.Error(codes.Internal, "session is invalidated")
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

	if !a.hasRequiredRole(claims.Roles, accessibleRoles) {
		return status.Error(codes.PermissionDenied, "user does not have required roles")
	}

	userObjectID, err := primitive.ObjectIDFromHex(claims.Subject)
	if err != nil {
		return status.Error(codes.Internal, "failed to get user")
	}

	user := &model.User{}
	err = database.UserCollection.FindOne(*ctx, bson.M{"_id": userObjectID}).Decode(&user)
	if err != nil {
		return status.Error(codes.Internal, "failed to get user")
	}

	user.SessionID = claims.SessionID
	*ctx = context.WithValue(*ctx, "user", user)
	return nil
}
