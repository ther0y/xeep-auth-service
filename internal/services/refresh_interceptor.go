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

		user, session, err := r.verify(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		if user != nil {
			ctx = context.WithValue(ctx, "user", user)
		}

		if session != nil {
			ctx = context.WithValue(ctx, "session", session)
		}

		return handler(ctx, req)
	}
}

func (r *RefreshInterceptor) verify(ctx context.Context, method string) (user *model.User, session *model.Session, err error) {
	_, ok := r.refreshableRoles[method]
	if !ok {
		// No roles required to access this method
		return nil, nil, nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	values := md.Get("refresh_token")
	if len(values) == 0 {
		return nil, nil, status.Error(codes.Unauthenticated, "refresh token is not provided")
	}

	refreshToken := values[0]

	isInvalidated, err := RefreshTokenManagerService.IsTokenInvalidated(refreshToken)
	if err != nil {
		return nil, nil, status.Error(codes.Internal, err.Error())
	}

	if isInvalidated {
		return nil, nil, status.Error(codes.Unauthenticated, "refresh token is invalidated")
	}

	claims, err := RefreshTokenManagerService.VerifyToken(refreshToken)
	if err != nil {
		// TODO: handle expired token
		// if ve, ok := err.(*jwt.ValidationError); ok {
		// 	if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
		// 		return nil, nil, status.Errorf(codes.AlreadyExists, "token is expired 2")
		// 	}
		// }
		return nil, nil, err
	}

	id, err := primitive.ObjectIDFromHex(claims.Subject)
	if err != nil {
		return nil, nil, status.Error(codes.Internal, err.Error())
	}

	user = &model.User{}
	err = database.UserCollection.FindOne(ctx, bson.M{"_id": id}).Decode(user)
	if err != nil {
		return nil, nil, status.Error(codes.Internal, err.Error())
	}

	session = &model.Session{}
	err = database.SessionCollection.FindOne(ctx, bson.M{"key": claims.Id}).Decode(&session)
	if err != nil {
		return nil, nil, status.Error(codes.Internal, err.Error())
	}

	if session.Key != claims.Id {
		return nil, nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}

	return user, session, nil
}
