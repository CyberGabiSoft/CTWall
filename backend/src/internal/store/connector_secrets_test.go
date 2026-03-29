package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeConnectorSecretKey(t *testing.T) {
	base64Key := "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	key, err := decodeConnectorSecretKey(base64Key)
	if err != nil {
		t.Fatalf("expected base64 key to decode: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	hexKey := "hex:3031323334353637383961626364656630313233343536373839616263646566"
	key, err = decodeConnectorSecretKey(hexKey)
	if err != nil {
		t.Fatalf("expected hex key to decode: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	if _, err := decodeConnectorSecretKey("short"); err == nil {
		t.Fatalf("expected invalid key error")
	}
}

func TestConnectorSecretCodecEncryptDecryptConfig(t *testing.T) {
	t.Setenv(connectorSecretEnvKey, "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	codec, err := newConnectorSecretCodecFromEnv()
	if err != nil {
		t.Fatalf("codec init: %v", err)
	}
	raw := json.RawMessage(`{
		"host":"smtp.local",
		"password":"super-secret",
		"nested":{"webhookUrl":"https://hooks.slack.local/abc"},
		"headers":[{"apiKey":"abc123"}]
	}`)
	encrypted, err := codec.encryptConfigJSON(raw)
	if err != nil {
		t.Fatalf("encrypt config: %v", err)
	}
	if strings.Contains(string(encrypted), "super-secret") {
		t.Fatalf("plaintext secret leaked in encrypted payload")
	}
	if strings.Contains(string(encrypted), "hooks.slack.local/abc") {
		t.Fatalf("plaintext webhook leaked in encrypted payload")
	}
	if !configHasEncryptedSecretPayload(encrypted) {
		t.Fatalf("expected encrypted payload marker")
	}

	decrypted, err := codec.decryptConfigJSON(encrypted)
	if err != nil {
		t.Fatalf("decrypt config: %v", err)
	}
	if !strings.Contains(string(decrypted), "super-secret") {
		t.Fatalf("expected decrypted password in payload")
	}
	if !strings.Contains(string(decrypted), "hooks.slack.local/abc") {
		t.Fatalf("expected decrypted webhook in payload")
	}
}

func TestMergeEmptySecretValuesWithExisting(t *testing.T) {
	incoming := map[string]any{
		"username": "bot",
		"botToken": "***",
		"nested": map[string]any{
			"password": "",
		},
	}
	existing := map[string]any{
		"botToken": "enc:v1:deadbeef",
		"nested": map[string]any{
			"password": "enc:v1:cafebabe",
		},
	}
	mergeEmptySecretValuesWithExisting(incoming, existing)
	if incoming["botToken"] != "enc:v1:deadbeef" {
		t.Fatalf("expected botToken to inherit existing encrypted value")
	}
	nested, ok := incoming["nested"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested map")
	}
	if nested["password"] != "enc:v1:cafebabe" {
		t.Fatalf("expected nested password to inherit existing encrypted value")
	}
}

func TestEncodeConnectorForWriteRequiresKeyForSecrets(t *testing.T) {
	store := &PostgresStore{connectorCodec: nil}
	_, err := store.encodeConnectorForWrite(json.RawMessage(`{"botToken":"xoxb-123"}`), nil)
	if err == nil {
		t.Fatalf("expected secret-without-key error")
	}

	out, err := store.encodeConnectorForWrite(json.RawMessage(`{"defaultChannel":"#alerts"}`), nil)
	if err != nil {
		t.Fatalf("expected non-secret config to pass without key: %v", err)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Fatalf("expected non-empty payload")
	}
}

func TestDecodeConnectorForReadFailsWhenEncryptedAndNoKey(t *testing.T) {
	store := &PostgresStore{connectorCodec: nil}
	item := &ConnectorConfig{
		ConnectorType: ConnectorTypeSlack,
		ConfigJSON:    json.RawMessage(`{"botToken":"enc:v1:deadbeef"}`),
	}
	if err := store.decodeConnectorForRead(item); err == nil {
		t.Fatalf("expected decode error without key")
	}
}
