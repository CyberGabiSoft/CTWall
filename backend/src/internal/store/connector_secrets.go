package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	connectorSecretEnvKey   = "APP_ENCRYPTION_KEY"
	connectorSecretPrefixV1 = "enc:v1:"
)

type connectorSecretCodec struct {
	aead cipher.AEAD
}

func newConnectorSecretCodecFromEnv() (*connectorSecretCodec, error) {
	raw := strings.TrimSpace(os.Getenv(connectorSecretEnvKey))
	if raw == "" {
		return nil, nil
	}
	key, err := decodeConnectorSecretKey(raw)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &connectorSecretCodec{aead: aead}, nil
}

func decodeConnectorSecretKey(raw string) ([]byte, error) {
	candidates := make([]string, 0, 2)
	candidates = append(candidates, raw)
	if strings.HasPrefix(raw, "base64:") {
		candidates = append(candidates, strings.TrimPrefix(raw, "base64:"))
	}
	if strings.HasPrefix(raw, "hex:") {
		candidates = append(candidates, strings.TrimPrefix(raw, "hex:"))
	}

	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if decoded, err := base64.StdEncoding.DecodeString(candidate); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
		if decoded, err := base64.RawStdEncoding.DecodeString(candidate); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
		if decoded, err := hex.DecodeString(candidate); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("%s must be a 32-byte key (base64/raw-base64 or hex)", connectorSecretEnvKey)
}

func (c *connectorSecretCodec) encryptString(plain string) (string, error) {
	if c == nil {
		return plain, nil
	}
	if plain == "" || strings.HasPrefix(plain, connectorSecretPrefixV1) {
		return plain, nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := c.aead.Seal(nil, nonce, []byte(plain), nil)
	payload := append(nonce, ciphertext...)
	return connectorSecretPrefixV1 + base64.RawStdEncoding.EncodeToString(payload), nil
}

func (c *connectorSecretCodec) decryptString(value string) (string, error) {
	if c == nil || !strings.HasPrefix(value, connectorSecretPrefixV1) {
		return value, nil
	}
	raw := strings.TrimPrefix(value, connectorSecretPrefixV1)
	data, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	nonceSize := c.aead.NonceSize()
	if len(data) <= nonceSize {
		return "", errors.New("invalid encrypted secret payload")
	}
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]
	plain, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (c *connectorSecretCodec) encryptConfigJSON(raw json.RawMessage) (json.RawMessage, error) {
	if c == nil {
		return raw, nil
	}
	cfg, err := unmarshalConfigObject(raw)
	if err != nil {
		return nil, err
	}
	if err := walkConfigSecrets(cfg, true, c); err != nil {
		return nil, err
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

func (c *connectorSecretCodec) decryptConfigJSON(raw json.RawMessage) (json.RawMessage, error) {
	if c == nil {
		return raw, nil
	}
	cfg, err := unmarshalConfigObject(raw)
	if err != nil {
		return nil, err
	}
	if err := walkConfigSecrets(cfg, false, c); err != nil {
		return nil, err
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

func configHasEncryptedSecretPayload(raw json.RawMessage) bool {
	cfg, err := unmarshalConfigObject(raw)
	if err != nil {
		return false
	}
	return walkConfigForEncryptedPayload(cfg)
}

func configHasSecretMaterial(raw json.RawMessage) bool {
	cfg, err := unmarshalConfigObject(raw)
	if err != nil {
		return false
	}
	return walkConfigForSecretMaterial(cfg)
}

func configHasUnencryptedSecretPayload(raw json.RawMessage) bool {
	cfg, err := unmarshalConfigObject(raw)
	if err != nil {
		return false
	}
	return walkConfigForUnencryptedSecretPayload(cfg)
}

func unmarshalConfigObject(raw json.RawMessage) (map[string]any, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return map[string]any{}, nil
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(trimmed), &cfg); err != nil {
		return nil, ErrInvalidPayload
	}
	if cfg == nil {
		return map[string]any{}, nil
	}
	return cfg, nil
}

func walkConfigSecrets(cfg map[string]any, encrypt bool, codec *connectorSecretCodec) error {
	for key, value := range cfg {
		if isConnectorSecretKey(key) {
			switch typed := value.(type) {
			case string:
				var out string
				var err error
				if encrypt {
					out, err = codec.encryptString(typed)
				} else {
					out, err = codec.decryptString(typed)
				}
				if err != nil {
					return err
				}
				cfg[key] = out
			case []any:
				for idx := range typed {
					switch item := typed[idx].(type) {
					case string:
						var out string
						var err error
						if encrypt {
							out, err = codec.encryptString(item)
						} else {
							out, err = codec.decryptString(item)
						}
						if err != nil {
							return err
						}
						typed[idx] = out
					case map[string]any:
						if err := walkConfigSecrets(item, encrypt, codec); err != nil {
							return err
						}
					}
				}
			}
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			if err := walkConfigSecrets(typed, encrypt, codec); err != nil {
				return err
			}
		case []any:
			for idx := range typed {
				if nested, ok := typed[idx].(map[string]any); ok {
					if err := walkConfigSecrets(nested, encrypt, codec); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func walkConfigForEncryptedPayload(cfg map[string]any) bool {
	for key, value := range cfg {
		if isConnectorSecretKey(key) {
			switch typed := value.(type) {
			case string:
				if strings.HasPrefix(typed, connectorSecretPrefixV1) {
					return true
				}
			case []any:
				for idx := range typed {
					switch item := typed[idx].(type) {
					case string:
						if strings.HasPrefix(item, connectorSecretPrefixV1) {
							return true
						}
					case map[string]any:
						if walkConfigForEncryptedPayload(item) {
							return true
						}
					}
				}
			}
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			if walkConfigForEncryptedPayload(typed) {
				return true
			}
		case []any:
			for idx := range typed {
				if nested, ok := typed[idx].(map[string]any); ok {
					if walkConfigForEncryptedPayload(nested) {
						return true
					}
				}
			}
		}
	}
	return false
}

func walkConfigForSecretMaterial(cfg map[string]any) bool {
	for key, value := range cfg {
		if isConnectorSecretKey(key) {
			switch typed := value.(type) {
			case string:
				if strings.TrimSpace(typed) != "" {
					return true
				}
			case []any:
				for idx := range typed {
					switch item := typed[idx].(type) {
					case string:
						if strings.TrimSpace(item) != "" {
							return true
						}
					case map[string]any:
						if walkConfigForSecretMaterial(item) {
							return true
						}
					}
				}
			}
		}
		switch typed := value.(type) {
		case map[string]any:
			if walkConfigForSecretMaterial(typed) {
				return true
			}
		case []any:
			for idx := range typed {
				if nested, ok := typed[idx].(map[string]any); ok {
					if walkConfigForSecretMaterial(nested) {
						return true
					}
				}
			}
		}
	}
	return false
}

func walkConfigForUnencryptedSecretPayload(cfg map[string]any) bool {
	for key, value := range cfg {
		if isConnectorSecretKey(key) {
			switch typed := value.(type) {
			case string:
				trimmed := strings.TrimSpace(typed)
				if trimmed != "" && !strings.HasPrefix(trimmed, connectorSecretPrefixV1) {
					return true
				}
			case []any:
				for idx := range typed {
					switch item := typed[idx].(type) {
					case string:
						trimmed := strings.TrimSpace(item)
						if trimmed != "" && !strings.HasPrefix(trimmed, connectorSecretPrefixV1) {
							return true
						}
					case map[string]any:
						if walkConfigForUnencryptedSecretPayload(item) {
							return true
						}
					}
				}
			}
		}
		switch typed := value.(type) {
		case map[string]any:
			if walkConfigForUnencryptedSecretPayload(typed) {
				return true
			}
		case []any:
			for idx := range typed {
				if nested, ok := typed[idx].(map[string]any); ok {
					if walkConfigForUnencryptedSecretPayload(nested) {
						return true
					}
				}
			}
		}
	}
	return false
}

func mergeEmptySecretValuesWithExisting(incoming, existing map[string]any) {
	if len(incoming) == 0 || len(existing) == 0 {
		return
	}
	for key, value := range incoming {
		current, ok := existing[key]
		if !ok {
			continue
		}
		if isConnectorSecretKey(key) {
			incomingSecret, incomingOK := value.(string)
			existingSecret, existingOK := current.(string)
			if incomingOK && existingOK {
				trimmedIncoming := strings.TrimSpace(incomingSecret)
				if (trimmedIncoming == "" || trimmedIncoming == "***") && strings.TrimSpace(existingSecret) != "" {
					incoming[key] = existingSecret
				}
			}
			continue
		}
		nestedIncoming, incomingOK := value.(map[string]any)
		nestedExisting, existingOK := current.(map[string]any)
		if incomingOK && existingOK {
			mergeEmptySecretValuesWithExisting(nestedIncoming, nestedExisting)
		}
	}
}

func isConnectorSecretKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return false
	}
	switch {
	case strings.Contains(normalized, "token"):
		return true
	case strings.Contains(normalized, "password"):
		return true
	case strings.Contains(normalized, "secret"):
		return true
	case normalized == "apikey" || normalized == "api_key":
		return true
	case strings.Contains(normalized, "webhook"):
		return true
	default:
		return false
	}
}
