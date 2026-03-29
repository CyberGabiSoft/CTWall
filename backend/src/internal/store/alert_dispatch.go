package store

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

type AlertDispatchMessageType string

const (
	AlertDispatchMessageTypeConfigApply AlertDispatchMessageType = "CONFIG_APPLY"
	AlertDispatchMessageTypeAlertEvent  AlertDispatchMessageType = "ALERT_EVENT"
)

type AlertDispatchEventState string

const (
	AlertDispatchEventStateFiring  AlertDispatchEventState = "FIRING"
	AlertDispatchEventStateResolve AlertDispatchEventState = "RESOLVED"
)

type AlertDispatchQueueState string

const (
	AlertDispatchQueueStatePending  AlertDispatchQueueState = "PENDING"
	AlertDispatchQueueStateInFlight AlertDispatchQueueState = "IN_FLIGHT"
	AlertDispatchQueueStateRetry    AlertDispatchQueueState = "RETRY"
	AlertDispatchQueueStateDone     AlertDispatchQueueState = "DONE"
	AlertDispatchQueueStateDead     AlertDispatchQueueState = "DEAD"
)

type AlertDispatchJob struct {
	ID               uuid.UUID               `json:"id"`
	MessageType      AlertDispatchMessageType `json:"messageType"`
	EventState       *AlertDispatchEventState `json:"eventState,omitempty"`
	ProjectID        *uuid.UUID               `json:"projectId,omitempty"`
	GroupID          *uuid.UUID               `json:"groupId,omitempty"`
	PayloadJSON      json.RawMessage          `json:"payloadJson"`
	State            AlertDispatchQueueState  `json:"state"`
	AttemptCount     int                      `json:"attemptCount"`
	NextAttemptAt    time.Time                `json:"nextAttemptAt"`
	ExpiresAt        *time.Time               `json:"expiresAt,omitempty"`
	LockedAt         *time.Time               `json:"lockedAt,omitempty"`
	LockedBy         string                   `json:"lockedBy,omitempty"`
	LastErrorCode    string                   `json:"lastErrorCode,omitempty"`
	LastErrorMessage string                   `json:"lastErrorMessage,omitempty"`
	DoneAt           *time.Time               `json:"doneAt,omitempty"`
	CreatedAt        time.Time                `json:"createdAt"`
	UpdatedAt        time.Time                `json:"updatedAt"`
}

type AlertDispatchEnqueueInput struct {
	MessageType   AlertDispatchMessageType
	EventState    *AlertDispatchEventState
	ProjectID     *uuid.UUID
	GroupID       *uuid.UUID
	PayloadJSON   json.RawMessage
	NextAttemptAt *time.Time
	ExpiresAt     *time.Time
}

func normalizeAlertDispatchMessageType(raw AlertDispatchMessageType) AlertDispatchMessageType {
	switch strings.ToUpper(strings.TrimSpace(string(raw))) {
	case string(AlertDispatchMessageTypeConfigApply):
		return AlertDispatchMessageTypeConfigApply
	case string(AlertDispatchMessageTypeAlertEvent):
		return AlertDispatchMessageTypeAlertEvent
	default:
		return ""
	}
}

func normalizeAlertDispatchEventState(raw AlertDispatchEventState) AlertDispatchEventState {
	switch strings.ToUpper(strings.TrimSpace(string(raw))) {
	case string(AlertDispatchEventStateFiring):
		return AlertDispatchEventStateFiring
	case string(AlertDispatchEventStateResolve):
		return AlertDispatchEventStateResolve
	default:
		return ""
	}
}

func normalizeAlertDispatchQueueState(raw AlertDispatchQueueState) AlertDispatchQueueState {
	switch strings.ToUpper(strings.TrimSpace(string(raw))) {
	case string(AlertDispatchQueueStatePending):
		return AlertDispatchQueueStatePending
	case string(AlertDispatchQueueStateInFlight):
		return AlertDispatchQueueStateInFlight
	case string(AlertDispatchQueueStateRetry):
		return AlertDispatchQueueStateRetry
	case string(AlertDispatchQueueStateDone):
		return AlertDispatchQueueStateDone
	case string(AlertDispatchQueueStateDead):
		return AlertDispatchQueueStateDead
	default:
		return ""
	}
}

