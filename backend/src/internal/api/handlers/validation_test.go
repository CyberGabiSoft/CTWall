package handlers

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizePlainText(t *testing.T) {
	input := "  hello\x00\nworld\t "
	if got := sanitizePlainText(input); got != "helloworld" {
		t.Fatalf("unexpected sanitizePlainText: %q", got)
	}
}

func TestValidateName(t *testing.T) {
	if _, err := validateName("name", " ", true); err == nil {
		t.Fatalf("expected required name error")
	}
	if _, err := validateName("name", strings.Repeat("a", maxNameLength+1), true); err == nil {
		t.Fatalf("expected name length error")
	}
	name, err := validateName("name", " Alpha\x00 ", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "Alpha" {
		t.Fatalf("unexpected sanitized name: %q", name)
	}
}

func TestValidateEmailPasswordAndFullName(t *testing.T) {
	if _, err := validateEmail("email", " ", true); err == nil {
		t.Fatalf("expected email required error")
	}
	if _, err := validateEmail("email", strings.Repeat("a", maxEmailLength+1), true); err == nil {
		t.Fatalf("expected email length error")
	}
	if _, err := validateEmail("email", "bad\x00@example.com", true); err == nil {
		t.Fatalf("expected email control error")
	}
	if _, err := validateEmail("email", "not-an-email", true); err == nil {
		t.Fatalf("expected email format error")
	}
	email, err := validateEmail("email", "user@example.com", true)
	if err != nil {
		t.Fatalf("unexpected email error: %v", err)
	}
	if email != "user@example.com" {
		t.Fatalf("unexpected email: %q", email)
	}

	if _, err := validatePassword("password", " ", true); err == nil {
		t.Fatalf("expected password required error")
	}
	if _, err := validatePassword("password", strings.Repeat("a", maxPasswordLength+1), true); err == nil {
		t.Fatalf("expected password length error")
	}
	if _, err := validatePassword("password", "bad\x00pass", true); err == nil {
		t.Fatalf("expected password control error")
	}
	password, err := validatePassword("password", "secret", true)
	if err != nil {
		t.Fatalf("unexpected password error: %v", err)
	}
	if password != "secret" {
		t.Fatalf("unexpected password: %q", password)
	}

	_, err = validateFullName("fullName", strings.Repeat("a", maxFullNameLength+1))
	if err == nil {
		t.Fatalf("expected fullName length error")
	}
	var fullName string
	fullName, err = validateFullName("fullName", " User \n")
	if err != nil {
		t.Fatalf("unexpected fullName error: %v", err)
	}
	if fullName != "User" {
		t.Fatalf("unexpected fullName: %q", fullName)
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	if _, err := validatePasswordStrength("password", "short"); err == nil {
		t.Fatalf("expected min length error")
	}
	if _, err := validatePasswordStrength("password", "alllowercase123!"); err == nil {
		t.Fatalf("expected uppercase requirement error")
	}
	if _, err := validatePasswordStrength("password", "ALLUPPERCASE123!"); err == nil {
		t.Fatalf("expected lowercase requirement error")
	}
	if _, err := validatePasswordStrength("password", "NoDigitsHere!"); err == nil {
		t.Fatalf("expected digit requirement error")
	}
	if _, err := validatePasswordStrength("password", "NoSpecials123"); err == nil {
		t.Fatalf("expected special requirement error")
	}
	if _, err := validatePasswordStrength("password", "Str0ng!Passw0rd"); err != nil {
		t.Fatalf("expected strong password, got %v", err)
	}
}

func TestSanitizeUserAgentAndIPAddress(t *testing.T) {
	if sanitizeUserAgent(" ") != "" {
		t.Fatalf("expected empty user agent")
	}
	long := strings.Repeat("a", maxUserAgentLength+10)
	if got := sanitizeUserAgent(long); utf8.RuneCountInString(got) != maxUserAgentLength {
		t.Fatalf("expected user agent truncation")
	}
}

func TestSanitizeContentType(t *testing.T) {
	if sanitizeContentType(" ") != "" {
		t.Fatalf("expected empty content type")
	}
	if sanitizeContentType("text/plain\x00") != "" {
		t.Fatalf("expected control chars to be rejected")
	}
	long := strings.Repeat("a", maxContentTypeLength+10)
	if got := sanitizeContentType(long); utf8.RuneCountInString(got) != maxContentTypeLength {
		t.Fatalf("expected content type truncation")
	}
}

func TestValidatePURL(t *testing.T) {
	if _, err := validatePURL(""); err == nil {
		t.Fatalf("expected empty purl error")
	}
	if _, err := validatePURL("not-a-purl"); err == nil {
		t.Fatalf("expected purl prefix error")
	}
	if _, err := validatePURL("pkg:/"); err == nil {
		t.Fatalf("expected purl name error")
	}
	if _, err := validatePURL("pkg:npm/leftpad@1.0.0\x00"); err == nil {
		t.Fatalf("expected control char error")
	}
	long := "pkg:npm/" + strings.Repeat("a", maxPURLLength)
	if _, err := validatePURL(long); err == nil {
		t.Fatalf("expected purl length error")
	}
	if value, err := validatePURL("pkg:npm/leftpad@1.0.0"); err != nil || value == "" {
		t.Fatalf("expected valid purl, got %q (%v)", value, err)
	}
}

func TestValidateTokenName(t *testing.T) {
	value, err := validateTokenName("name", "")
	if err != nil || value != "" {
		t.Fatalf("expected empty token name, got %q (%v)", value, err)
	}
	if _, err := validateTokenName("name", strings.Repeat("a", maxNameLength+1)); err == nil {
		t.Fatalf("expected token name length error")
	}
	value, err = validateTokenName("name", " token ")
	if err != nil {
		t.Fatalf("unexpected token name error: %v", err)
	}
	if value != "token" {
		t.Fatalf("unexpected token name: %q", value)
	}
}

func TestNormalizeTags(t *testing.T) {
	normalized, err := normalizeTags([]string{" alpha ", "", "beta"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(normalized) != 2 || normalized[0] != "alpha" || normalized[1] != "beta" {
		t.Fatalf("unexpected normalized tags: %v", normalized)
	}
	if _, err := normalizeTags([]string{strings.Repeat("a", maxTagLength+1)}); err == nil {
		t.Fatalf("expected tag length error")
	}
	tooMany := make([]string, maxTagCount+1)
	for i := range tooMany {
		tooMany[i] = "tag"
	}
	if _, err := normalizeTags(tooMany); err == nil {
		t.Fatalf("expected tag count error")
	}
}

func TestParseSbomTypeField(t *testing.T) {
	sbomType, provided, err := parseSbomTypeField("")
	if err != nil || provided || sbomType.Standard != "" {
		t.Fatalf("expected empty sbomType, got %+v provided=%v err=%v", sbomType, provided, err)
	}
	if _, _, err := parseSbomTypeField("unknown"); err == nil {
		t.Fatalf("expected sbomType validation error")
	}
	sbomType, provided, err = parseSbomTypeField(`{"standard":"spdx","specVersion":"2.3"}`)
	if err != nil || !provided {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if sbomType.Standard != "spdx" || sbomType.SpecVersion != "2.3" {
		t.Fatalf("unexpected sbomType: %+v", sbomType)
	}
	if _, _, err := parseSbomTypeField("SPDX-JSON"); err == nil {
		t.Fatalf("expected sbomType JSON object validation error")
	}
	if _, _, err := parseSbomTypeField(`{"standard":"cyclonedx","specVersion":"bad"}`); err == nil {
		t.Fatalf("expected specVersion validation error")
	}
}

func TestParseSbomProducerField(t *testing.T) {
	producer, provided, err := parseSbomProducerField("")
	if err != nil || provided || producer != "" {
		t.Fatalf("expected empty producer, got %q provided=%v err=%v", producer, provided, err)
	}
	producer, provided, err = parseSbomProducerField("syft")
	if err != nil || !provided || producer != "syft" {
		t.Fatalf("unexpected producer parse: %q (%v)", producer, err)
	}
	if _, _, err := parseSbomProducerField("unknown"); err == nil {
		t.Fatalf("expected producer validation error")
	}
}

func TestValidateMetadataJSON(t *testing.T) {
	value, err := validateMetadataJSON("")
	if err != nil || value != nil {
		t.Fatalf("expected empty metadata result, got %v (%v)", value, err)
	}
	if _, err := validateMetadataJSON("{bad"); err == nil {
		t.Fatalf("expected metadata JSON error")
	}
	if _, err := validateMetadataJSON(strings.Repeat("a", maxMetadataBytes+1)); err == nil {
		t.Fatalf("expected metadata size error")
	}
	value, err = validateMetadataJSON(`{"ok":true}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(value) {
		t.Fatalf("expected valid metadata JSON")
	}
}

func TestValidateSearchQuery(t *testing.T) {
	if _, err := validateSearchQuery(" "); err == nil {
		t.Fatalf("expected query required error")
	}
	if _, err := validateSearchQuery(strings.Repeat("a", maxSearchQueryRunes+1)); err == nil {
		t.Fatalf("expected query length error")
	}
	query, err := validateSearchQuery(" pay\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if query != "pay" {
		t.Fatalf("unexpected sanitized query: %q", query)
	}
}

func TestValidateTagFilter(t *testing.T) {
	value, err := validateTagFilter("")
	if err != nil || value != "" {
		t.Fatalf("expected empty tag, got %q (%v)", value, err)
	}
	if _, err := validateTagFilter(strings.Repeat("a", maxTagLength+1)); err == nil {
		t.Fatalf("expected tag length error")
	}
	value, err = validateTagFilter(" alpha\t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "alpha" {
		t.Fatalf("unexpected sanitized tag: %q", value)
	}
}
