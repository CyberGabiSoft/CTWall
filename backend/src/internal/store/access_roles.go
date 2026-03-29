package store

import "strings"

const (
	ProjectRoleAdmin  = "ADMIN"
	ProjectRoleWriter = "WRITER"
	ProjectRoleReader = "READER"
)

const (
	GroupMemberRoleOwner  = "OWNER"
	GroupMemberRoleEditor = "EDITOR"
	GroupMemberRoleViewer = "VIEWER"
)

const (
	ProductGroupGrantRoleEditor = "EDITOR"
	ProductGroupGrantRoleViewer = "VIEWER"
)

func NormalizeProjectRole(role string) string {
	return strings.ToUpper(strings.TrimSpace(role))
}

func IsValidProjectRole(role string) bool {
	switch NormalizeProjectRole(role) {
	case ProjectRoleAdmin, ProjectRoleWriter, ProjectRoleReader:
		return true
	default:
		return false
	}
}

func NormalizeGroupMemberRole(role string) string {
	return strings.ToUpper(strings.TrimSpace(role))
}

func ProjectRoleAtLeast(role string, required string) bool {
	return projectRoleRank(role) >= projectRoleRank(required)
}

func projectRoleRank(role string) int {
	switch NormalizeProjectRole(role) {
	case ProjectRoleAdmin:
		return 3
	case ProjectRoleWriter:
		return 2
	case ProjectRoleReader:
		return 1
	default:
		return 0
	}
}
