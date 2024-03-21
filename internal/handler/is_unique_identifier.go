package handler

import (
	"context"
	"fmt"
	"github.com/ther0y/xeep-auth-service/auther"
	"github.com/ther0y/xeep-auth-service/internal/model"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Service) IsUniqueUserIdentifier(ctx context.Context, req *auther.IsUniqueUserIdentifierRequest) (*auther.IsUniqueUserIdentifierResponse, error) {
	user := model.User{}
	err := user.FindByIdentifier(ctx, req.Identifier)
	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			return &auther.IsUniqueUserIdentifierResponse{IsUnique: true}, nil
		}

		return nil, status.Error(codes.Internal, fmt.Errorf("failed to find user by identifier: %w", err).Error())
	}

	if user.ID.IsZero() {
		return &auther.IsUniqueUserIdentifierResponse{IsUnique: true}, nil
	}

	return &auther.IsUniqueUserIdentifierResponse{IsUnique: false}, nil
}
