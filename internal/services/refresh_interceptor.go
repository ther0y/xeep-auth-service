package services

import (
	"context"
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

	md, ok := metadata.FromIncomingContext(*ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	values := md.Get("refresh_token")
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, "refresh token is not provided")
	}

	refreshToken := values[0]

	claims, err := RefreshTokenManagerService.GetClaims(refreshToken)
	if err != nil {
		return err
	}

	isInvalidated, err := IsSessionInvalidated(claims.SessionID)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	if isInvalidated {
		return status.Error(codes.Unauthenticated, "refresh token is invalidated")
	}

	latestRevision, err := database.GetSessionsLatestRevision(claims.SessionID)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	if latestRevision != claims.Revision {
		err = InvalidateAllSessionData(claims.SessionID, claims.ExpiresAt)
		if err != nil {
			return err
		}

		return status.Error(codes.Unauthenticated, "refresh token is invalidated")
	}

	userObjectID, err := primitive.ObjectIDFromHex(claims.Subject)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	user := &model.User{}
	err = database.UserCollection.FindOne(*ctx, bson.M{"_id": userObjectID}).Decode(user)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	*ctx = context.WithValue(*ctx, "user", user)

	sessionObjectID, err := primitive.ObjectIDFromHex(claims.SessionID)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	session := &model.Session{}
	err = database.SessionCollection.FindOne(*ctx, bson.M{"_id": sessionObjectID}).Decode(&session)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	*ctx = context.WithValue(*ctx, "session", session)

	return nil
}
