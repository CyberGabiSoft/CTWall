package handlers

import (
	"time"

	"backend/internal/models"

	"github.com/google/uuid"
)

type testResponse struct {
	ID          uuid.UUID       `json:"id"`
	ScopeID     uuid.UUID       `json:"scopeId"`
	Name        string          `json:"name"`
	SbomType    sbomTypePayload `json:"sbomType"`
	IsPublic    bool            `json:"isPublic"`
	PublicToken string          `json:"publicToken,omitempty"`
	ArchivedAt  *time.Time      `json:"archivedAt,omitempty"`
	CreatedAt   time.Time       `json:"createdAt"`
	UpdatedAt   time.Time       `json:"updatedAt"`
}

func mapTestsResponse(items []models.Test) []testResponse {
	responses := make([]testResponse, 0, len(items))
	for _, item := range items {
		responses = append(responses, testResponse{
			ID:          item.ID,
			ScopeID:     item.ScopeID,
			Name:        item.Name,
			SbomType:    sbomTypePayload{Standard: item.SbomStandard, SpecVersion: item.SbomSpecVersion},
			IsPublic:    item.IsPublic,
			PublicToken: item.PublicToken,
			ArchivedAt:  item.ArchivedAt,
			CreatedAt:   item.CreatedAt,
			UpdatedAt:   item.UpdatedAt,
		})
	}
	return responses
}
