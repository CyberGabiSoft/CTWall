package handlers

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"backend/internal/sbom"
)

const (
	maxNameLength        = 120
	maxEmailLength       = 120
	maxPasswordLength    = 120
	minPasswordLength    = 12
	maxNicknameLength    = 64
	maxFullNameLength    = 120
	maxUserAgentLength   = 256
	maxTagLength         = 64
	maxTagCount          = 50
	maxMetadataBytes     = 64 * 1024
	maxSbomMetadataBytes = 64 * 1024
	maxSearchQueryRunes  = 200
	maxContentTypeLength = 255
	maxPURLLength        = 2048
)

type sbomTypePayload struct {
	Standard    string `json:"standard"`
	SpecVersion string `json:"specVersion"`
}

func sanitizePlainText(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(trimmed))
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func validateName(field string, value string, required bool) (string, error) {
	clean := sanitizePlainText(value)
	if clean == "" {
		if required {
			return "", fmt.Errorf("field '%s' is required", field)
		}
		return "", nil
	}
	if utf8.RuneCountInString(clean) > maxNameLength {
		return "", fmt.Errorf("field '%s' must be at most %d characters", field, maxNameLength)
	}
	return clean, nil
}

func validateEmail(field string, value string, required bool) (string, error) {
	clean := strings.TrimSpace(value)
	if clean == "" {
		if required {
			return "", fmt.Errorf("field '%s' is required", field)
		}
		return "", nil
	}
	if utf8.RuneCountInString(clean) > maxEmailLength {
		return "", fmt.Errorf("field '%s' must be at most %d characters", field, maxEmailLength)
	}
	if containsControl(clean) {
		return "", fmt.Errorf("field '%s' contains invalid characters", field)
	}
	if _, err := mail.ParseAddress(clean); err != nil {
		return "", fmt.Errorf("field '%s' must be a valid email address", field)
	}
	return clean, nil
}

func validatePassword(field string, value string, required bool) (string, error) {
	clean := strings.TrimSpace(value)
	if clean == "" {
		if required {
			return "", fmt.Errorf("field '%s' is required", field)
		}
		return "", nil
	}
	if utf8.RuneCountInString(clean) > maxPasswordLength {
		return "", fmt.Errorf("field '%s' must be at most %d characters", field, maxPasswordLength)
	}
	if containsControl(clean) {
		return "", fmt.Errorf("field '%s' contains invalid characters", field)
	}
	return clean, nil
}

func validatePasswordStrength(field string, value string) (string, error) {
	clean, err := validatePassword(field, value, true)
	if err != nil {
		return "", err
	}
	if utf8.RuneCountInString(clean) < minPasswordLength {
		return "", fmt.Errorf("field '%s' must be at least %d characters", field, minPasswordLength)
	}
	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, r := range clean {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsLetter(r) || unicode.IsNumber(r):
			// keep existing flags
		default:
			hasSpecial = true
		}
	}
	if !hasLower || !hasUpper || !hasDigit || !hasSpecial {
		return "", fmt.Errorf("field '%s' must include uppercase, lowercase, digit, and special character", field)
	}
	return clean, nil
}

func validateFullName(field string, value string) (string, error) {
	clean := sanitizePlainText(value)
	if clean == "" {
		return "", nil
	}
	if utf8.RuneCountInString(clean) > maxFullNameLength {
		return "", fmt.Errorf("field '%s' must be at most %d characters", field, maxFullNameLength)
	}
	return clean, nil
}

func validateNickname(field string, value string, required bool) (string, error) {
	clean := sanitizePlainText(value)
	if clean == "" {
		if required {
			return "", fmt.Errorf("field '%s' is required", field)
		}
		return "", nil
	}
	if utf8.RuneCountInString(clean) > maxNicknameLength {
		return "", fmt.Errorf("field '%s' must be at most %d characters", field, maxNicknameLength)
	}
	return clean, nil
}

func validateTokenName(field string, value string) (string, error) {
	clean := sanitizePlainText(value)
	if clean == "" {
		return "", nil
	}
	if utf8.RuneCountInString(clean) > maxNameLength {
		return "", fmt.Errorf("field '%s' must be at most %d characters", field, maxNameLength)
	}
	return clean, nil
}

func sanitizeUserAgent(value string) string {
	clean := sanitizePlainText(value)
	if clean == "" {
		return ""
	}
	if utf8.RuneCountInString(clean) > maxUserAgentLength {
		runes := []rune(clean)
		return string(runes[:maxUserAgentLength])
	}
	return clean
}

func sanitizeContentType(value string) string {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return ""
	}
	if containsControl(clean) {
		return ""
	}
	if utf8.RuneCountInString(clean) > maxContentTypeLength {
		runes := []rune(clean)
		return string(runes[:maxContentTypeLength])
	}
	return clean
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func normalizeTags(tags []string) ([]string, error) {
	normalized := make([]string, 0, len(tags))
	for _, tag := range tags {
		clean := sanitizePlainText(tag)
		if clean == "" {
			continue
		}
		if utf8.RuneCountInString(clean) > maxTagLength {
			return nil, fmt.Errorf("tags must be at most %d characters", maxTagLength)
		}
		normalized = append(normalized, clean)
		if len(normalized) > maxTagCount {
			return nil, fmt.Errorf("no more than %d tags are allowed", maxTagCount)
		}
	}
	return normalized, nil
}

func parseSbomTypeField(value string) (sbom.Type, bool, error) {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return sbom.Type{}, false, nil
	}
	if !strings.HasPrefix(clean, "{") {
		return sbom.Type{}, true, fmt.Errorf("field 'sbomType' must be a valid JSON object")
	}

	var payload sbomTypePayload
	if err := json.Unmarshal([]byte(clean), &payload); err != nil {
		return sbom.Type{}, true, fmt.Errorf("field 'sbomType' must be valid JSON")
	}
	standard, err := sbom.NormalizeStandard(payload.Standard)
	if err != nil || standard == "" {
		return sbom.Type{}, true, fmt.Errorf("field 'sbomType.standard' must be one of: cyclonedx, spdx")
	}
	spec, err := sbom.NormalizeSpecVersion(payload.SpecVersion)
	if err != nil {
		return sbom.Type{}, true, fmt.Errorf("field 'sbomType.specVersion' must match pattern ^(unknown|\\d+(\\.\\d+){0,2})$")
	}
	return sbom.Type{Standard: standard, SpecVersion: spec}, true, nil
}

func parseSbomProducerField(value string) (sbom.Producer, bool, error) {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return "", false, nil
	}
	producer, err := sbom.NormalizeProducer(clean)
	if err != nil || producer == "" {
		return "", true, fmt.Errorf("field 'sbomProducer' must be one of: trivy, syft, grype, other")
	}
	return producer, true, nil
}

func validatePURL(value string) (string, error) {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return "", fmt.Errorf("component PURL is required")
	}
	if utf8.RuneCountInString(clean) > maxPURLLength {
		return "", fmt.Errorf("component PURL must be at most %d characters", maxPURLLength)
	}
	if containsControl(clean) {
		return "", fmt.Errorf("component PURL contains invalid characters")
	}
	if !strings.HasPrefix(clean, "pkg:") {
		return "", fmt.Errorf("component PURL must start with 'pkg:'")
	}
	base := strings.TrimPrefix(clean, "pkg:")
	base = strings.SplitN(base, "?", 2)[0]
	base = strings.SplitN(base, "#", 2)[0]
	parts := strings.SplitN(base, "/", 2)
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" {
		return "", fmt.Errorf("component PURL must include a package type and name")
	}
	namePart := strings.SplitN(parts[1], "@", 2)[0]
	if strings.TrimSpace(namePart) == "" {
		return "", fmt.Errorf("component PURL must include a package name")
	}
	return sbom.NormalizePURL(clean), nil
}

func validateMetadataJSON(raw string) (json.RawMessage, error) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return nil, nil
	}
	if len(clean) > maxMetadataBytes {
		return nil, fmt.Errorf("field 'metadataJson' must be at most %d bytes", maxMetadataBytes)
	}
	if !json.Valid([]byte(clean)) {
		return nil, fmt.Errorf("field 'metadataJson' must be valid JSON")
	}
	return json.RawMessage(clean), nil
}

func validateSbomMetadataJSON(raw []byte) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxSbomMetadataBytes {
		return nil, fmt.Errorf("SBOM metadata exceeds %d bytes", maxSbomMetadataBytes)
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("SBOM metadata must be valid JSON")
	}
	return json.RawMessage(raw), nil
}

func validateSearchQuery(value string) (string, error) {
	clean := sanitizePlainText(value)
	if clean == "" {
		return "", fmt.Errorf("query parameter 'q' is required")
	}
	if utf8.RuneCountInString(clean) > maxSearchQueryRunes {
		return "", fmt.Errorf("query parameter 'q' must be at most %d characters", maxSearchQueryRunes)
	}
	return clean, nil
}

func validateOptionalSearchQuery(field string, value string) (string, error) {
	clean := sanitizePlainText(value)
	if clean == "" {
		return "", nil
	}
	if utf8.RuneCountInString(clean) > maxSearchQueryRunes {
		return "", fmt.Errorf("query parameter '%s' must be at most %d characters", field, maxSearchQueryRunes)
	}
	return clean, nil
}

func validateTagFilter(value string) (string, error) {
	clean := sanitizePlainText(value)
	if clean == "" {
		return "", nil
	}
	if utf8.RuneCountInString(clean) > maxTagLength {
		return "", fmt.Errorf("query parameter 'tag' must be at most %d characters", maxTagLength)
	}
	return clean, nil
}
