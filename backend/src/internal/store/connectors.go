package store

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ConnectorType defines supported integration providers for Settings > Connectors.
type ConnectorType string

const (
	ConnectorTypeDiscord              ConnectorType = "DISCORD"
	ConnectorTypeSMTP                 ConnectorType = "SMTP"
	ConnectorTypeMSTeamsV2            ConnectorType = "MSTEAMSV2"
	ConnectorTypeJira                 ConnectorType = "JIRA"
	ConnectorTypeAlertmanagerExternal ConnectorType = "ALERTMANAGER_EXTERNAL"
	ConnectorTypeOpsgenie             ConnectorType = "OPSGENIE"
	ConnectorTypePagerDuty            ConnectorType = "PAGERDUTY"
	ConnectorTypePushover             ConnectorType = "PUSHOVER"
	ConnectorTypeRocketChat           ConnectorType = "ROCKETCHAT"
	ConnectorTypeSlack                ConnectorType = "SLACK"
	ConnectorTypeSNS                  ConnectorType = "SNS"
	ConnectorTypeTelegram             ConnectorType = "TELEGRAM"
	ConnectorTypeVictorOps            ConnectorType = "VICTOROPS"
	ConnectorTypeWebex                ConnectorType = "WEBEX"
	ConnectorTypeWebhook              ConnectorType = "WEBHOOK"
	ConnectorTypeWeChat               ConnectorType = "WECHAT"
)

// ConnectorScopeType defines where a connector config applies.
type ConnectorScopeType string

const (
	ConnectorScopeGlobal  ConnectorScopeType = "GLOBAL"
	ConnectorScopeProject ConnectorScopeType = "PROJECT"
	ConnectorScopeProduct ConnectorScopeType = "PRODUCT"
	ConnectorScopeScope   ConnectorScopeType = "SCOPE"
	ConnectorScopeTest    ConnectorScopeType = "TEST"
)

// ConnectorTestStatus stores the last connector test result.
type ConnectorTestStatus string

const (
	ConnectorTestNotConfigured ConnectorTestStatus = "NOT_CONFIGURED"
	ConnectorTestPassed        ConnectorTestStatus = "PASSED"
	ConnectorTestFailed        ConnectorTestStatus = "FAILED"
)

// ConnectorConfig stores connector configuration metadata and runtime status.
type ConnectorConfig struct {
	ID              uuid.UUID           `json:"id"`
	ConnectorType   ConnectorType       `json:"connectorType"`
	ScopeType       ConnectorScopeType  `json:"scopeType"`
	ScopeID         *uuid.UUID          `json:"scopeId,omitempty"`
	ConfigJSON      json.RawMessage     `json:"configJson"`
	IsEnabled       bool                `json:"isEnabled"`
	LastTestStatus  ConnectorTestStatus `json:"lastTestStatus"`
	LastTestAt      *time.Time          `json:"lastTestAt,omitempty"`
	LastTestMessage string              `json:"lastTestMessage,omitempty"`
	CreatedAt       time.Time           `json:"createdAt"`
	UpdatedAt       time.Time           `json:"updatedAt"`
}

var connectorTypes = []ConnectorType{
	ConnectorTypeDiscord,
	ConnectorTypeSMTP,
	ConnectorTypeMSTeamsV2,
	ConnectorTypeJira,
	ConnectorTypeAlertmanagerExternal,
	ConnectorTypeOpsgenie,
	ConnectorTypePagerDuty,
	ConnectorTypePushover,
	ConnectorTypeRocketChat,
	ConnectorTypeSlack,
	ConnectorTypeSNS,
	ConnectorTypeTelegram,
	ConnectorTypeVictorOps,
	ConnectorTypeWebex,
	ConnectorTypeWebhook,
	ConnectorTypeWeChat,
}

var connectorTypesDisabledInMVP = map[ConnectorType]struct{}{
	ConnectorTypeMSTeamsV2:  {},
	ConnectorTypeOpsgenie:   {},
	ConnectorTypePagerDuty:  {},
	ConnectorTypePushover:   {},
	ConnectorTypeRocketChat: {},
	ConnectorTypeTelegram:   {},
	ConnectorTypeVictorOps:  {},
	ConnectorTypeWebex:      {},
	ConnectorTypeWebhook:    {},
	ConnectorTypeWeChat:     {},
}

var connectorTypeSet = buildConnectorTypeSet(connectorTypes)

// AllConnectorTypes returns the supported connector types in stable order.
func AllConnectorTypes() []ConnectorType {
	return append([]ConnectorType(nil), connectorTypes...)
}

// IsConnectorTypeEnabledInMVP reports whether connector type is currently enabled in MVP scope.
func IsConnectorTypeEnabledInMVP(value ConnectorType) bool {
	_, disabled := connectorTypesDisabledInMVP[value]
	return !disabled
}

// AllMVPConnectorTypes returns only connector types enabled for current MVP scope.
func AllMVPConnectorTypes() []ConnectorType {
	all := AllConnectorTypes()
	out := make([]ConnectorType, 0, len(all))
	for _, connectorType := range all {
		if IsConnectorTypeEnabledInMVP(connectorType) {
			out = append(out, connectorType)
		}
	}
	return out
}

// NormalizeConnectorType returns a canonical connector type value.
func NormalizeConnectorType(raw string) ConnectorType {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "DISCORD":
		return ConnectorTypeDiscord
	case "JIRA":
		return ConnectorTypeJira
	case "ALERTMANAGER_EXTERNAL", "ALERTMANAGEREXTERNAL":
		return ConnectorTypeAlertmanagerExternal
	case "MSTEAMSV2", "MS_TEAMS_V2", "MSTEAMS_V2":
		return ConnectorTypeMSTeamsV2
	case "OPSGENIE":
		return ConnectorTypeOpsgenie
	case "PAGERDUTY":
		return ConnectorTypePagerDuty
	case "PUSHOVER":
		return ConnectorTypePushover
	case "ROCKETCHAT", "ROCKET_CHAT":
		return ConnectorTypeRocketChat
	case "SLACK":
		return ConnectorTypeSlack
	case "SNS":
		return ConnectorTypeSNS
	case "SMTP":
		return ConnectorTypeSMTP
	case "TELEGRAM":
		return ConnectorTypeTelegram
	case "VICTOROPS":
		return ConnectorTypeVictorOps
	case "WEBEX":
		return ConnectorTypeWebex
	case "WEBHOOK":
		return ConnectorTypeWebhook
	case "WECHAT":
		return ConnectorTypeWeChat
	default:
		return ConnectorType("")
	}
}

// ValidConnectorType reports whether the connector type is supported.
func ValidConnectorType(value ConnectorType) bool {
	_, ok := connectorTypeSet[value]
	return ok
}

// ValidConnectorTestStatus reports whether test status value is supported.
func ValidConnectorTestStatus(value ConnectorTestStatus) bool {
	switch value {
	case ConnectorTestNotConfigured, ConnectorTestPassed, ConnectorTestFailed:
		return true
	default:
		return false
	}
}

func buildConnectorTypeSet(values []ConnectorType) map[ConnectorType]struct{} {
	set := make(map[ConnectorType]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}
