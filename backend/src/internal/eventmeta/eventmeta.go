package eventmeta

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Category is a low-cardinality, backend-defined enum for audit log categorization.
// Values must match DOCS/todo/important_system_events_table.md (section 2).
type Category string

const (
	CategoryAuthN         Category = "authn"
	CategoryAuthZ         Category = "authz"
	CategoryAccount       Category = "account"
	CategoryToken         Category = "token"
	CategoryConfig        Category = "config"
	CategoryDataImport    Category = "data_import"
	CategoryDataExport    Category = "data_export"
	CategoryMalware       Category = "malware"
	CategorySourceSync    Category = "source_sync"
	CategoryAPIError      Category = "api_error"
	CategoryRateLimit     Category = "rate_limit"
	CategoryInfraDB       Category = "infra_db"
	CategoryInfraStorage  Category = "infra_storage"
	CategoryInfraExternal Category = "infra_external"
	CategorySystem        Category = "system"
)

// Severity is a required field for audit log entries stored in DB.
// Values must match the portal logging docs: INFO/WARN/ERROR.
type Severity string

const (
	SeverityInfo  Severity = "INFO"
	SeverityWarn  Severity = "WARN"
	SeverityError Severity = "ERROR"
)

// MinRole defines the minimum role required to view an audit log entry in the UI/API.
type MinRole string

const (
	MinRoleRead  MinRole = "read"
	MinRoleWrite MinRole = "write"
	MinRoleAdmin MinRole = "admin"
)

var ErrInvalidDetails = errors.New("invalid audit log details")

func ValidCategory(value string) bool {
	switch Category(strings.TrimSpace(value)) {
	case CategoryAuthN,
		CategoryAuthZ,
		CategoryAccount,
		CategoryToken,
		CategoryConfig,
		CategoryDataImport,
		CategoryDataExport,
		CategoryMalware,
		CategorySourceSync,
		CategoryAPIError,
		CategoryRateLimit,
		CategoryInfraDB,
		CategoryInfraStorage,
		CategoryInfraExternal,
		CategorySystem:
		return true
	default:
		return false
	}
}

func ValidSeverity(value string) bool {
	switch Severity(strings.TrimSpace(value)) {
	case SeverityInfo, SeverityWarn, SeverityError:
		return true
	default:
		return false
	}
}

func ValidMinRole(value string) bool {
	switch MinRole(strings.TrimSpace(value)) {
	case MinRoleRead, MinRoleWrite, MinRoleAdmin:
		return true
	default:
		return false
	}
}

const maxEventKeyLength = 240

var eventKeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,239}$`)

// NormalizeActionToKeySegment converts an action like "LOGIN_SUCCESS" to "login_success".
// It keeps the result low-cardinality and safe for indexing/aggregation.
func NormalizeActionToKeySegment(action string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		return ""
	}
	// Allow only [a-z0-9_] as action segment; collapse everything else to underscore.
	var b strings.Builder
	b.Grow(len(action))
	prevUnderscore := false
	for _, r := range action {
		isAZ := r >= 'a' && r <= 'z'
		is09 := r >= '0' && r <= '9'
		if isAZ || is09 {
			b.WriteRune(r)
			prevUnderscore = false
			continue
		}
		if !prevUnderscore {
			b.WriteByte('_')
			prevUnderscore = true
		}
	}
	out := strings.Trim(b.String(), "_")
	return out
}

// DefaultEventKey builds a stable event_key for an audit record when code did not provide one.
// Format: "<category>.<normalized_action>".
func DefaultEventKey(category Category, action string) string {
	cat := strings.TrimSpace(string(category))
	if !ValidCategory(cat) {
		cat = string(CategorySystem)
	}
	seg := NormalizeActionToKeySegment(action)
	if seg == "" {
		seg = "unknown_action"
	}
	key := cat + "." + seg
	if len(key) > maxEventKeyLength {
		key = key[:maxEventKeyLength]
	}
	return key
}

// ValidEventKey enforces a low-cardinality, safe event_key format.
// Allowed: lowercase letters, digits, '.', '_', '-'. Must not be empty.
func ValidEventKey(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxEventKeyLength {
		return false
	}
	return eventKeyRe.MatchString(value)
}

// ValidateDetails enforces that the details JSON contains required keys and valid enum values.
// It intentionally validates only the minimal contract required by docs:
// - category (enum)
// - severity (enum)
// - min_role (enum)
func ValidateDetails(raw json.RawMessage) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: empty", ErrInvalidDetails)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%w: invalid json: %v", ErrInvalidDetails, err)
	}
	category, _ := m["category"].(string)
	if !ValidCategory(category) {
		return fmt.Errorf("%w: invalid category", ErrInvalidDetails)
	}
	severity, _ := m["severity"].(string)
	if !ValidSeverity(severity) {
		return fmt.Errorf("%w: invalid severity", ErrInvalidDetails)
	}
	minRole, _ := m["min_role"].(string)
	if !ValidMinRole(minRole) {
		return fmt.Errorf("%w: invalid min_role", ErrInvalidDetails)
	}
	eventKey, _ := m["event_key"].(string)
	if !ValidEventKey(eventKey) {
		return fmt.Errorf("%w: invalid event_key", ErrInvalidDetails)
	}
	return nil
}

// NormalizeCategoryToSystem rewrites unknown category values to "system".
//
// This is a safety valve so we do not lose audit records due to an accidental
// invalid category in runtime. The invalid value is NOT preserved in the DB.
//
// NOTE: It does not accept missing/empty category. That remains a validation error.
func NormalizeCategoryToSystem(raw json.RawMessage) (normalized json.RawMessage, changed bool, err error) {
	if len(raw) == 0 {
		return nil, false, fmt.Errorf("%w: empty", ErrInvalidDetails)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false, fmt.Errorf("%w: invalid json: %v", ErrInvalidDetails, err)
	}
	category, ok := m["category"].(string)
	if !ok {
		return raw, false, nil
	}
	if ValidCategory(category) {
		return raw, false, nil
	}
	m["category"] = string(CategorySystem)
	b, err := json.Marshal(m)
	if err != nil {
		return nil, false, fmt.Errorf("%w: marshal normalized: %v", ErrInvalidDetails, err)
	}
	return b, true, nil
}
