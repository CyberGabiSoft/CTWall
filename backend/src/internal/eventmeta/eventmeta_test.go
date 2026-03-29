package eventmeta

import (
	"encoding/json"
	"testing"
)

func TestValidateDetails(t *testing.T) {
	t.Parallel()

	ok := func(m map[string]any) json.RawMessage {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}

	tests := []struct {
		name    string
		raw     json.RawMessage
		wantErr bool
	}{
		{
			name: "valid",
			raw: ok(map[string]any{
				"category":  string(CategoryAuthN),
				"severity":  string(SeverityWarn),
				"min_role":  string(MinRoleWrite),
				"traceId":   "abc",
				"event_key": "authn.login_failure.invalid_password",
			}),
		},
		{name: "empty", raw: nil, wantErr: true},
		{name: "invalid_json", raw: json.RawMessage("{"), wantErr: true},
		{
			name: "missing_category",
			raw: ok(map[string]any{
				"severity": string(SeverityWarn),
				"min_role": string(MinRoleWrite),
			}),
			wantErr: true,
		},
		{
			name: "bad_category",
			raw: ok(map[string]any{
				"category": "nope",
				"severity": string(SeverityWarn),
				"min_role": string(MinRoleWrite),
			}),
			wantErr: true,
		},
		{
			name: "bad_severity",
			raw: ok(map[string]any{
				"category": string(CategoryAuthN),
				"severity": "FATAL",
				"min_role": string(MinRoleWrite),
			}),
			wantErr: true,
		},
		{
			name: "bad_min_role",
			raw: ok(map[string]any{
				"category": string(CategoryAuthN),
				"severity": string(SeverityWarn),
				"min_role": "owner",
			}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateDetails(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeCategoryToSystem(t *testing.T) {
	t.Parallel()

	raw := func(m map[string]any) json.RawMessage {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}

	t.Run("no_change_when_valid", func(t *testing.T) {
		t.Parallel()
		normalized, changed, err := NormalizeCategoryToSystem(raw(map[string]any{
			"category": string(CategoryAuthN),
			"severity": string(SeverityWarn),
			"min_role": string(MinRoleWrite),
			"event_key": "authn.test_event",
		}))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if changed {
			t.Fatalf("changed=true want false")
		}
		if err := ValidateDetails(normalized); err != nil {
			t.Fatalf("ValidateDetails: %v", err)
		}
	})

	t.Run("rewrite_invalid_category", func(t *testing.T) {
		t.Parallel()
		normalized, changed, err := NormalizeCategoryToSystem(raw(map[string]any{
			"category": "not-a-real-category",
			"severity": string(SeverityWarn),
			"min_role": string(MinRoleWrite),
			"event_key": "authn.test_event",
		}))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !changed {
			t.Fatalf("changed=false want true")
		}
		var got map[string]any
		if err := json.Unmarshal(normalized, &got); err != nil {
			t.Fatalf("unmarshal normalized: %v", err)
		}
		if got["category"] != string(CategorySystem) {
			t.Fatalf("category=%v want %v", got["category"], CategorySystem)
		}
		if err := ValidateDetails(normalized); err != nil {
			t.Fatalf("ValidateDetails: %v", err)
		}
	})
}
