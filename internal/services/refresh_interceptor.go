package services

import (
	"context"
	"fmt"
	"github.com/ther0y/xeep-auth-service/internal/database"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type RefreshInterceptor struct {
	refreshableRoles map[string][]string
}

func NewRefreshInterceptor(refreshableRoles map[string][]string) *RefreshInterceptor {
	return &RefreshInterceptor{refreshableRoles}
}

func (r *RefreshInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {

		err := r.authorize(&ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func (r *RefreshInterceptor) authorize(ctx *context.Context, method string) (err error) {
	_, ok := r.refreshableRoles[method]
	if !ok {
		// No roles required to access this method
		return nil
	}

	refreshToken, err := getRefreshTokenFromContext(*ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	claims, err := RefreshTokenManagerService.GetClaims(refreshToken)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	if err := checkSessionValidityAndRevision(claims); err != nil {
		return err
	}

	if err := setUserAndSessionInContext(ctx, &claims.SessionClaims); err != nil {
		return err
	}

	return nil
}

func getRefreshTokenFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	values := md.Get("refresh_token")
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "refresh token is not provided")
	}

	return values[0], nil
}

func checkSessionValidityAndRevision(claims *RefreshTokenClaims) error {
	isSessionInvalidated, err := IsSessionInvalidated(claims.SessionID)
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to check if session is invalidated: %w", err).Error())
	}

	if isSessionInvalidated {
		return status.Error(codes.Unauthenticated, "session is invalidated")
	}

	latestRevision, err := database.GetSessionsLatestRevision(claims.SessionID)
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to get the latest revision: %w", err).Error())
	}

	if latestRevision != claims.Revision {
		err = InvalidateSessionData(claims.SessionID, claims.ExpiresAt)
		if err != nil {
			return err
		}

		return status.Error(codes.Unauthenticated, "refresh token is invalidated")
	}

	return nil
}

func setUserAndSessionInContext(ctx *context.Context, claims *SessionClaims) error {
	userObjectID, err := primitive.ObjectIDFromHex(claims.Subject)
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to convert user id to object id: %w", err).Error())
	}

	user := &model.User{}
	err = database.UserCollection.FindOne(*ctx, bson.M{"_id": userObjectID}).Decode(&user)
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to get user from database: %w", err).Error())
	}

	sessionObjectID, err := primitive.ObjectIDFromHex(claims.SessionID)
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to convert session id to object id: %w", err).Error())
	}

	session := &model.Session{}
	err = database.SessionCollection.FindOne(*ctx, bson.M{"_id": sessionObjectID}).Decode(&session)
	if err != nil {
		return status.Error(codes.Internal, fmt.Errorf("failed to get session from database: %w", err).Error())
	}

	*ctx = context.WithValue(*ctx, "user", user)
	*ctx = context.WithValue(*ctx, "session", session)

	return nil
}
