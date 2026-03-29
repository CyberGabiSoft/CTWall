package handlers

import "github.com/google/uuid"

type ingestInput struct {
	productID       *uuid.UUID
	scopeID         *uuid.UUID
	testID          *uuid.UUID
	productName     string
	scopeName       string
	testName        string
	sbomStandard    string
	sbomSpecVersion string
}

type resolveError struct {
	status int
	title  string
	detail string
	err    error
}
