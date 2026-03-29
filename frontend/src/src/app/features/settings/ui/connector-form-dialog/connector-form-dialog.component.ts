import { CommonModule } from '@angular/common';
import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, ValidatorFn, Validators } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatSelectModule } from '@angular/material/select';
import {
  AdminConnector,
  ConnectorUpsertRequest,
  SlackConnectorConfig,
  SmtpAuthMode,
  SmtpConnectorConfig,
  SmtpEncryptionMode,
  SmtpVerifyMode
} from '../../data-access/settings.types';
import { validateDedicatedConnectorConfig } from './connector-form-dialog.validators';

export interface ConnectorFormDialogData {
  connector: AdminConnector;
}

type DedicatedFieldType = 'text' | 'textarea' | 'password' | 'url' | 'number' | 'boolean' | 'select';

interface DedicatedSelectOption {
  readonly value: string;
  readonly label: string;
}

interface DedicatedConnectorField {
  readonly control: string;
  readonly output: string;
  readonly label: string;
  readonly type: DedicatedFieldType;
  readonly required?: boolean;
  readonly maxLength?: number;
  readonly hint?: string;
  readonly defaultValue?: string | number | boolean;
  readonly min?: number;
  readonly max?: number;
  readonly options?: readonly DedicatedSelectOption[];
}

interface DedicatedConnectorSchema {
  readonly fields: readonly DedicatedConnectorField[];
}

interface ConnectorFieldExample {
  readonly label: string;
  readonly value: string;
}

interface ConnectorTemplateVariable {
  readonly token: string;
  readonly description: string;
}

const connectorMessageTemplatePlaceholder =
  'CTWall {{severity}} | {{product}}/{{scope}}/{{test}} | {{alert_type}}';
const repeatIntervalExample = '30m';

const connectorMessageTemplateVariables: readonly ConnectorTemplateVariable[] = [
  { token: '{{project}}', description: 'Project name (or project ID fallback)' },
  { token: '{{product}}', description: 'Product name' },
  { token: '{{scope}}', description: 'Scope name' },
  { token: '{{test}}', description: 'Test name' },
  { token: '{{component_purl}}', description: 'Component PURL from malware occurrence context' },
  { token: '{{severity}}', description: 'Alert severity (INFO/WARNING/ERROR)' },
  { token: '{{finding_count}}', description: 'Number of grouped occurrences' },
  { token: '{{dedup_key}}', description: 'Alert group deduplication key' },
  { token: '{{alert_type}}', description: 'Alert type, e.g. malware.detected' }
];

const smtpConnectorFieldExamples: readonly ConnectorFieldExample[] = [
  { label: 'Host', value: 'smtp.example.com' },
  { label: 'Port', value: '587' },
  { label: 'Authentication', value: 'login' },
  { label: 'Encryption', value: 'starttls' },
  { label: 'Verify mode', value: 'peer' },
  { label: 'Timeout (seconds)', value: '10' },
  { label: 'Repeat interval', value: repeatIntervalExample },
  { label: 'Username', value: 'ctwall-notify' },
  { label: 'Password', value: 'example-smtp-secret' },
  { label: 'From email', value: 'ctwall@example.com' },
  { label: 'From name', value: 'CTWall Alerts' },
  { label: 'Reply-To', value: 'security@example.com' },
  { label: 'Domain (HELO/EHLO)', value: 'mail.example.com' },
  { label: 'Send resolved notifications', value: 'true' },
  { label: 'Message template', value: connectorMessageTemplatePlaceholder }
];

const slackConnectorFieldExamples: readonly ConnectorFieldExample[] = [
  { label: 'Webhook URL', value: 'https://hooks.slack.com/services/T00000000/B00000000/EXAMPLE' },
  { label: 'Bot token', value: 'xoxb-example-bot-token' },
  { label: 'Default channel', value: '#security-alerts' },
  { label: 'Bot display name', value: 'CTWall Bot' },
  { label: 'Repeat interval', value: repeatIntervalExample },
  { label: 'Send resolved notifications', value: 'true' },
  { label: 'Message template', value: connectorMessageTemplatePlaceholder }
];

const dedicatedConnectorFieldExamples: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  discord: {
    webhook_url: 'https://discord.com/api/webhooks/123456789012345678/example',
    send_resolved: 'true'
  },
  msteamsv2: {
    webhook_url: 'https://prod-00.westeurope.logic.azure.com/workflows/example/triggers/manual/paths/invoke',
    send_resolved: 'true'
  },
  jira: {
    base_url: 'https://jira.example.com',
    deployment_mode: 'auto',
    auth_mode: 'api_token',
    request_timeout_seconds: '10',
    email: 'alerts@example.com',
    api_token: 'example-jira-api-token',
    username: 'jira-bot',
    password: 'example-jira-password'
  },
  alertmanager_external: {
    base_url: 'https://alertmanager.example.com',
    auth_mode: 'none',
    username: 'alertmanager-user',
    password: 'example-alertmanager-password',
    token: 'example-alertmanager-bearer-token',
    timeout_seconds: '10',
    send_resolved: 'true',
    allow_self_signed: 'false'
  },
  opsgenie: {
    api_key: 'example-opsgenie-api-key',
    api_url: 'https://api.opsgenie.com',
    send_resolved: 'true'
  },
  pagerduty: {
    routing_key: '0123456789abcdef0123456789abcdef',
    send_resolved: 'true'
  },
  pushover: {
    user_key: 'uQiRzpo4DXghDmr9QzzfQu27cmVRsG',
    token: 'azGDORePK8gMaC0QOYAMyEEuzJnyUi',
    send_resolved: 'true'
  },
  rocketchat: {
    webhook_url: 'https://chat.example.com/hooks/example',
    channel: '#ctwall-alerts',
    send_resolved: 'true'
  },
  sns: {
    topic_arn: 'arn:aws:sns:us-east-1:123456789012:ctwall-alerts',
    api_url: 'https://sns.us-east-1.amazonaws.com',
    region: 'us-east-1',
    access_key: 'AKIAEXAMPLEACCESS',
    secret_key: 'example-sns-secret-key',
    send_resolved: 'true'
  },
  telegram: {
    bot_token: '123456789:exampleTelegramBotToken',
    chat_id: '-1001234567890',
    send_resolved: 'true'
  },
  victorops: {
    api_key: 'example-victorops-api-key',
    routing_key: 'ctwall-alerts',
    send_resolved: 'true'
  },
  webex: {
    api_url: 'https://webexapis.com/v1/messages',
    room_id: 'Y2lzY29zcGFyazovL3VzL1JPT00vZXhhbXBsZQ',
    bearer_token: 'example-webex-bearer-token',
    send_resolved: 'true'
  },
  webhook: {
    url: 'https://hooks.example.com/ctwall/alerts',
    max_alerts: '100',
    send_resolved: 'true'
  },
  wechat: {
    api_secret: 'example-wechat-secret',
    corp_id: 'ww1234567890abcdef',
    agent_id: '1000002',
    to_user: '@all',
    to_party: '2',
    to_tag: '5',
    send_resolved: 'true'
  }
};

const sendResolvedField: DedicatedConnectorField = {
  control: 'sendResolved',
  output: 'send_resolved',
  label: 'Send resolved notifications',
  type: 'boolean',
  defaultValue: true,
  hint: 'When enabled, Alertmanager sends notifications for resolved alerts too.'
};

const repeatIntervalField: DedicatedConnectorField = {
  control: 'repeatInterval',
  output: 'repeat_interval',
  label: 'Repeat interval',
  type: 'text',
  maxLength: 32,
  hint: 'Optional per-connector reminder interval (for example 15m, 1h, 90m).'
};

const messageTemplateField: DedicatedConnectorField = {
  control: 'messageTemplate',
  output: 'message_template',
  label: 'Message template',
  type: 'textarea',
  maxLength: 2000,
  hint: 'Optional custom message body. Use variables listed below.'
};

const dedicatedConnectorSchemas: Readonly<Record<string, DedicatedConnectorSchema>> = {
  discord: {
    fields: [
      {
        control: 'webhookUrl',
        output: 'webhook_url',
        label: 'Webhook URL',
        type: 'url',
        required: true,
        maxLength: 1024,
        hint: 'Discord incoming webhook URL.'
      },
      sendResolvedField
    ]
  },
  msteamsv2: {
    fields: [
      {
        control: 'webhookUrl',
        output: 'webhook_url',
        label: 'Webhook URL',
        type: 'url',
        required: true,
        maxLength: 1024,
        hint: 'Microsoft Teams Workflows webhook URL (v2).'
      },
      sendResolvedField
    ]
  },
  jira: {
    fields: [
      {
        control: 'baseUrl',
        output: 'base_url',
        label: 'Base URL',
        type: 'url',
        required: true,
        maxLength: 1024,
        hint: 'Jira base URL, for example https://jira.example.com.'
      },
      {
        control: 'deploymentMode',
        output: 'deployment_mode',
        label: 'Deployment mode',
        type: 'select',
        defaultValue: 'auto',
        required: true,
        options: [
          { value: 'auto', label: 'Auto detect (recommended)' },
          { value: 'cloud', label: 'Cloud (REST v3)' },
          { value: 'datacenter', label: 'Data Center (REST v2)' }
        ]
      },
      {
        control: 'authMode',
        output: 'auth_mode',
        label: 'Auth mode',
        type: 'select',
        defaultValue: 'api_token',
        required: true,
        options: [
          { value: 'api_token', label: 'API token (Cloud)' },
          { value: 'basic', label: 'Basic (Data Center)' }
        ]
      },
      {
        control: 'requestTimeoutSeconds',
        output: 'request_timeout_seconds',
        label: 'Request timeout (seconds)',
        type: 'number',
        required: true,
        defaultValue: 10,
        min: 1,
        max: 60,
        hint: 'HTTP timeout for Jira API test and runtime calls.'
      },
      {
        control: 'email',
        output: 'email',
        label: 'Email',
        type: 'text',
        maxLength: 254,
        hint: 'Required when auth mode is api_token.'
      },
      {
        control: 'apiToken',
        output: 'api_token',
        label: 'API token',
        type: 'password',
        maxLength: 255,
        hint: 'Required when auth mode is api_token.'
      },
      {
        control: 'username',
        output: 'username',
        label: 'Username',
        type: 'text',
        maxLength: 255,
        hint: 'Required when auth mode is basic.'
      },
      {
        control: 'password',
        output: 'password',
        label: 'Password',
        type: 'password',
        maxLength: 255,
        hint: 'Required when auth mode is basic.'
      }
    ]
  },
  alertmanager_external: {
    fields: [
      {
        control: 'baseUrl',
        output: 'base_url',
        label: 'Base URL',
        type: 'url',
        required: true,
        maxLength: 1024,
        hint: 'External Alertmanager base URL, for example https://alertmanager.example.com.'
      },
      {
        control: 'authMode',
        output: 'auth_mode',
        label: 'Auth mode',
        type: 'select',
        defaultValue: 'none',
        required: true,
        options: [
          { value: 'none', label: 'None' },
          { value: 'basic', label: 'Basic' },
          { value: 'bearer', label: 'Bearer token' }
        ]
      },
      {
        control: 'username',
        output: 'username',
        label: 'Username',
        type: 'text',
        maxLength: 255,
        hint: 'Required when auth mode is basic.'
      },
      {
        control: 'password',
        output: 'password',
        label: 'Password',
        type: 'password',
        maxLength: 255,
        hint: 'Required when auth mode is basic.'
      },
      {
        control: 'token',
        output: 'token',
        label: 'Bearer token',
        type: 'password',
        maxLength: 1024,
        hint: 'Required when auth mode is bearer.'
      },
      {
        control: 'timeoutSeconds',
        output: 'timeout_seconds',
        label: 'Request timeout (seconds)',
        type: 'number',
        required: true,
        defaultValue: 10,
        min: 1,
        max: 60
      },
      sendResolvedField,
      {
        control: 'allowSelfSigned',
        output: 'allow_self_signed',
        label: 'Allow self-signed TLS certificates',
        type: 'boolean',
        defaultValue: false,
        hint: 'Enable only for trusted internal environments.'
      }
    ]
  },
  opsgenie: {
    fields: [
      {
        control: 'apiKey',
        output: 'api_key',
        label: 'API key',
        type: 'password',
        required: true,
        maxLength: 255
      },
      {
        control: 'apiUrl',
        output: 'api_url',
        label: 'API URL',
        type: 'url',
        maxLength: 1024,
        hint: 'Optional override (default Opsgenie API endpoint is used if empty).'
      },
      sendResolvedField
    ]
  },
  pagerduty: {
    fields: [
      {
        control: 'routingKey',
        output: 'routing_key',
        label: 'Routing key',
        type: 'password',
        required: true,
        maxLength: 255
      },
      sendResolvedField
    ]
  },
  pushover: {
    fields: [
      {
        control: 'userKey',
        output: 'user_key',
        label: 'User key',
        type: 'password',
        required: true,
        maxLength: 255
      },
      {
        control: 'token',
        output: 'token',
        label: 'Application token',
        type: 'password',
        required: true,
        maxLength: 255
      },
      sendResolvedField
    ]
  },
  rocketchat: {
    fields: [
      {
        control: 'webhookUrl',
        output: 'webhook_url',
        label: 'Webhook URL',
        type: 'url',
        required: true,
        maxLength: 1024
      },
      {
        control: 'channel',
        output: 'channel',
        label: 'Default channel',
        type: 'text',
        maxLength: 128
      },
      sendResolvedField
    ]
  },
  sns: {
    fields: [
      {
        control: 'topicArn',
        output: 'topic_arn',
        label: 'Topic ARN',
        type: 'text',
        required: true,
        maxLength: 512
      },
      {
        control: 'apiUrl',
        output: 'api_url',
        label: 'API URL',
        type: 'url',
        maxLength: 1024,
        hint: 'Optional endpoint override (for example LocalStack: http://ctwall-localstack:4566).'
      },
      {
        control: 'region',
        output: 'region',
        label: 'Region',
        type: 'text',
        maxLength: 64,
        hint: 'Optional SigV4 region (for example us-east-1).'
      },
      {
        control: 'accessKey',
        output: 'access_key',
        label: 'Access key',
        type: 'text',
        maxLength: 255,
        hint: 'Optional static credential (required for some emulators).'
      },
      {
        control: 'secretKey',
        output: 'secret_key',
        label: 'Secret key',
        type: 'password',
        maxLength: 255,
        hint: 'Optional static credential secret (required for some emulators).'
      },
      sendResolvedField
    ]
  },
  telegram: {
    fields: [
      {
        control: 'botToken',
        output: 'bot_token',
        label: 'Bot token',
        type: 'password',
        required: true,
        maxLength: 255
      },
      {
        control: 'chatId',
        output: 'chat_id',
        label: 'Chat ID',
        type: 'text',
        required: true,
        maxLength: 255
      },
      sendResolvedField
    ]
  },
  victorops: {
    fields: [
      {
        control: 'apiKey',
        output: 'api_key',
        label: 'API key',
        type: 'password',
        required: true,
        maxLength: 255
      },
      {
        control: 'routingKey',
        output: 'routing_key',
        label: 'Routing key',
        type: 'text',
        required: true,
        maxLength: 255
      },
      sendResolvedField
    ]
  },
  webex: {
    fields: [
      {
        control: 'apiUrl',
        output: 'api_url',
        label: 'API URL',
        type: 'url',
        required: true,
        maxLength: 1024,
        hint: 'For example https://webexapis.com/v1/messages.'
      },
      {
        control: 'roomId',
        output: 'room_id',
        label: 'Room ID',
        type: 'text',
        required: true,
        maxLength: 255
      },
      {
        control: 'bearerToken',
        output: 'bearer_token',
        label: 'Bearer token',
        type: 'password',
        maxLength: 255
      },
      sendResolvedField
    ]
  },
  webhook: {
    fields: [
      {
        control: 'url',
        output: 'url',
        label: 'Target URL',
        type: 'url',
        required: true,
        maxLength: 1024
      },
      {
        control: 'maxAlerts',
        output: 'max_alerts',
        label: 'Max alerts per batch',
        type: 'number',
        min: 1,
        max: 1000,
        hint: 'Optional limit for alerts sent in one webhook request.'
      },
      sendResolvedField
    ]
  },
  wechat: {
    fields: [
      {
        control: 'apiSecret',
        output: 'api_secret',
        label: 'API secret',
        type: 'password',
        required: true,
        maxLength: 255
      },
      {
        control: 'corpId',
        output: 'corp_id',
        label: 'Corp ID',
        type: 'text',
        required: true,
        maxLength: 255
      },
      {
        control: 'agentId',
        output: 'agent_id',
        label: 'Agent ID',
        type: 'text',
        maxLength: 64
      },
      {
        control: 'toUser',
        output: 'to_user',
        label: 'To user',
        type: 'text',
        maxLength: 255
      },
      {
        control: 'toParty',
        output: 'to_party',
        label: 'To party',
        type: 'text',
        maxLength: 255
      },
      {
        control: 'toTag',
        output: 'to_tag',
        label: 'To tag',
        type: 'text',
        maxLength: 255
      },
      sendResolvedField
    ]
  }
};

const connectorsWithoutMessageTemplate = new Set<string>(['jira', 'alertmanager_external']);
const connectorsWithoutRepeatInterval = new Set<string>(['jira', 'alertmanager_external']);

const withRepeatIntervalField = (
  connectorType: string,
  schema: DedicatedConnectorSchema | null
): DedicatedConnectorSchema | null => {
  if (!schema) {
    return null;
  }
  if (connectorsWithoutRepeatInterval.has(connectorType)) {
    return schema;
  }
  if (schema.fields.some((field) => field.output === repeatIntervalField.output)) {
    return schema;
  }
  return {
    fields: [...schema.fields, repeatIntervalField]
  };
};

const withMessageTemplateField = (
  connectorType: string,
  schema: DedicatedConnectorSchema | null
): DedicatedConnectorSchema | null => {
  if (!schema) {
    return null;
  }
  if (connectorsWithoutMessageTemplate.has(connectorType)) {
    return schema;
  }
  if (schema.fields.some((field) => field.output === messageTemplateField.output)) {
    return schema;
  }
  return {
    fields: [...schema.fields, messageTemplateField]
  };
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const alertmanagerDurationPattern = /^[0-9]+(?:ms|s|m|h)(?:[0-9]+(?:ms|s|m|h))*$/;

@Component({
  selector: 'app-connector-form-dialog',
  imports: [
    CommonModule,
    ReactiveFormsModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatCheckboxModule,
    MatSelectModule
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './connector-form-dialog.component.html',
  styleUrl: './connector-form-dialog.component.scss'
})
export class ConnectorFormDialogComponent {
  readonly data = inject<ConnectorFormDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(
    MatDialogRef<ConnectorFormDialogComponent, ConnectorUpsertRequest | null>
  );
  private readonly fb = inject(NonNullableFormBuilder);
  private readonly connectorType = (this.data.connector.type ?? '').toLowerCase();
  private readonly smtpConnector = this.connectorType === 'smtp';
  private readonly slackConnector = this.connectorType === 'slack';
  private readonly dedicatedSchema = withMessageTemplateField(
    this.connectorType,
    withRepeatIntervalField(this.connectorType, dedicatedConnectorSchemas[this.connectorType] ?? null)
  );
  private readonly normalizedConnectorConfig = this.normalizeConfigKeys(this.data.connector.config);
  private readonly smtpConfig = this.parseSmtpConfig(this.data.connector.config);
  private readonly slackConfig = this.parseSlackConfig(this.data.connector.config);

  readonly parseError = signal<string | null>(null);
  readonly isSmtpConnector = this.smtpConnector;
  readonly isSlackConnector = this.slackConnector;
  readonly isDedicatedConnector = !this.smtpConnector && !this.slackConnector && this.dedicatedSchema !== null;
  readonly dedicatedFields = this.dedicatedSchema?.fields ?? [];
  readonly dedicatedInputFields = this.dedicatedFields.filter((field) => field.type !== 'boolean');
  readonly dedicatedBooleanFields = this.dedicatedFields.filter((field) => field.type === 'boolean');
  readonly hasDedicatedMessageTemplateField = this.dedicatedFields.some(
    (field) => this.normalizeFieldKey(field.output) === 'message_template'
  );
  readonly messageTemplateVariables = connectorMessageTemplateVariables;
  readonly messageTemplatePlaceholder = connectorMessageTemplatePlaceholder;
  readonly smtpFieldExamples = smtpConnectorFieldExamples;
  readonly slackFieldExamples = slackConnectorFieldExamples;
  readonly dedicatedFieldExamples = this.buildDedicatedFieldExamples();
  readonly smtpAuthOptions: Array<{ value: SmtpAuthMode; label: string }> = [
    { value: 'login', label: 'login (username + password)' },
    { value: 'none', label: 'none' }
  ];
  readonly smtpEncryptionOptions: Array<{ value: SmtpEncryptionMode; label: string }> = [
    { value: 'starttls', label: 'starttls' },
    { value: 'tls', label: 'tls' },
    { value: 'none', label: 'none (dev only)' }
  ];
  readonly smtpVerifyOptions: Array<{ value: SmtpVerifyMode; label: string }> = [
    { value: 'peer', label: 'peer' },
    { value: 'none', label: 'none' }
  ];

  readonly jsonForm = this.fb.group({
    enabled: [this.data.connector.enabled],
    configText: [this.prettyJson(this.data.connector.config), [Validators.required]]
  });
  readonly dedicatedForm = this.buildDedicatedForm();
  readonly smtpForm = this.fb.group({
    enabled: [this.data.connector.enabled],
    host: [this.smtpConfig.host, [Validators.required, Validators.maxLength(255)]],
    port: [String(this.smtpConfig.port), [Validators.required, Validators.pattern('^[0-9]{1,5}$')]],
    username: [this.smtpConfig.username, [Validators.maxLength(255)]],
    password: [this.smtpConfig.password, [Validators.maxLength(255)]],
    fromEmail: [this.smtpConfig.fromEmail, [Validators.required, Validators.email, Validators.maxLength(254)]],
    fromName: [this.smtpConfig.fromName, [Validators.maxLength(255)]],
    replyTo: [this.smtpConfig.replyTo, [Validators.email, Validators.maxLength(254)]],
    domain: [this.smtpConfig.domain, [Validators.maxLength(255)]],
    auth: [this.smtpConfig.auth],
    encryption: [this.smtpConfig.encryption],
    verifyMode: [this.smtpConfig.verifyMode],
    timeoutSeconds: [String(this.smtpConfig.timeoutSeconds), [Validators.required, Validators.pattern('^[0-9]{1,2}$')]],
    repeatInterval: [this.smtpConfig.repeatInterval, [Validators.maxLength(32)]],
    sendResolved: [this.smtpConfig.sendResolved],
    messageTemplate: [this.smtpConfig.messageTemplate, [Validators.maxLength(2000)]]
  });
  readonly slackForm = this.fb.group({
    enabled: [this.data.connector.enabled],
    webhookUrl: [this.slackConfig.webhookUrl, [Validators.maxLength(1024)]],
    botToken: [this.slackConfig.botToken, [Validators.maxLength(255)]],
    defaultChannel: [this.slackConfig.defaultChannel, [Validators.maxLength(120)]],
    username: [this.slackConfig.username, [Validators.maxLength(120)]],
    repeatInterval: [this.slackConfig.repeatInterval, [Validators.maxLength(32)]],
    sendResolved: [this.slackConfig.sendResolved],
    messageTemplate: [this.slackConfig.messageTemplate, [Validators.maxLength(2000)]]
  });

  cancel(): void {
    this.ref.close(null);
  }

  submit(): void {
    this.parseError.set(null);
    if (this.isSmtpConnector) {
      this.submitSmtp();
      return;
    }
    if (this.isSlackConnector) {
      this.submitSlack();
      return;
    }
    if (this.isDedicatedConnector) {
      this.submitDedicated();
      return;
    }
    this.submitJson();
  }

  fieldInputType(field: DedicatedConnectorField): string {
    switch (field.type) {
      case 'password':
        return 'password';
      case 'url':
        return 'url';
      case 'number':
        return 'text';
      default:
        return 'text';
    }
  }

  fieldInputMode(field: DedicatedConnectorField): string | null {
    return field.type === 'number' ? 'numeric' : null;
  }

  fieldSelectOptions(field: DedicatedConnectorField): readonly DedicatedSelectOption[] {
    return field.options ?? [];
  }

  fieldHasError(field: DedicatedConnectorField, errorKey: string): boolean {
    const control = this.dedicatedForm.controls[field.control];
    return !!control && control.touched && control.hasError(errorKey);
  }

  private buildDedicatedFieldExamples(): ConnectorFieldExample[] {
    const connectorExamples = dedicatedConnectorFieldExamples[this.connectorType] ?? {};
    return this.dedicatedFields.map((field) => ({
      label: field.label,
      value: this.resolveDedicatedFieldExample(field, connectorExamples)
    }));
  }

  private resolveDedicatedFieldExample(
    field: DedicatedConnectorField,
    connectorExamples: Readonly<Record<string, string>>
  ): string {
    const normalizedOutput = this.normalizeFieldKey(field.output);
    const explicit = connectorExamples[normalizedOutput];
    if (explicit) {
      return explicit;
    }
    if (normalizedOutput === 'message_template') {
      return connectorMessageTemplatePlaceholder;
    }
    if (normalizedOutput === 'repeat_interval') {
      return repeatIntervalExample;
    }
    if (field.type === 'boolean') {
      if (typeof field.defaultValue === 'boolean') {
        return field.defaultValue ? 'true' : 'false';
      }
      return 'true';
    }
    if (field.type === 'select') {
      if (typeof field.defaultValue === 'string' && field.defaultValue.trim()) {
        return field.defaultValue;
      }
      const first = field.options?.[0]?.value ?? '';
      return first || 'value';
    }
    if (field.type === 'number') {
      if (typeof field.defaultValue === 'number' && Number.isFinite(field.defaultValue)) {
        return String(field.defaultValue);
      }
      if (typeof field.min === 'number' && Number.isFinite(field.min)) {
        return String(field.min);
      }
      return '10';
    }
    if (field.type === 'url') {
      return 'https://example.com/path';
    }
    if (field.type === 'password') {
      return 'example-secret';
    }
    return `example-${this.normalizeFieldKey(field.output)}`;
  }

  private submitJson(): void {
    if (this.jsonForm.invalid) {
      this.jsonForm.markAllAsTouched();
      return;
    }

    const parsed = this.parseConfig(this.jsonForm.controls.configText.value);
    if (!parsed) {
      this.parseError.set('Config must be a valid JSON object.');
      return;
    }

    this.ref.close({
      enabled: this.jsonForm.controls.enabled.value,
      config: parsed
    });
  }

  private submitDedicated(): void {
    if (this.dedicatedForm.invalid) {
      this.dedicatedForm.markAllAsTouched();
      return;
    }
    const config: Record<string, unknown> = {};
    for (const field of this.dedicatedFields) {
      const control = this.dedicatedForm.controls[field.control];
      if (!control) {
        continue;
      }
      if (field.type === 'boolean') {
        const boolValue = Boolean(control.value);
        const defaultBool = typeof field.defaultValue === 'boolean' ? field.defaultValue : false;
        if (boolValue !== defaultBool || field.required) {
          config[field.output] = boolValue;
        }
        continue;
      }

      const rawValue = String(control.value ?? '').trim();
      if (rawValue === '') {
        if (this.isPreservableSecretField(field.output) && this.hasMaskedStoredSecret(field.output)) {
          // Keep existing secret on save when the UI field is intentionally left empty.
          config[field.output] = '***';
          continue;
        }
        if (field.required) {
          this.parseError.set(`${field.label} is required.`);
          return;
        }
        continue;
      }

      if (field.type === 'url' && !this.isHTTPURL(rawValue)) {
        this.parseError.set(`${field.label} must be a valid http:// or https:// URL.`);
        return;
      }
      if (this.normalizeFieldKey(field.output) === 'repeat_interval' && !this.isValidRepeatInterval(rawValue)) {
        this.parseError.set(`${field.label} must use Alertmanager duration format (for example 15m, 1h, 90m).`);
        return;
      }

      if (field.type === 'number') {
        const parsed = Number.parseInt(rawValue, 10);
        if (!Number.isFinite(parsed)) {
          this.parseError.set(`${field.label} must be a numeric value.`);
          return;
        }
        if (typeof field.min === 'number' && parsed < field.min) {
          this.parseError.set(`${field.label} must be greater or equal to ${field.min}.`);
          return;
        }
        if (typeof field.max === 'number' && parsed > field.max) {
          this.parseError.set(`${field.label} must be lower or equal to ${field.max}.`);
          return;
        }
        config[field.output] = parsed;
        continue;
      }

      config[field.output] = rawValue;
    }

    const validationError = validateDedicatedConnectorConfig(this.connectorType, config);
    if (validationError) {
      this.parseError.set(validationError);
      return;
    }

    this.ref.close({
      enabled: this.dedicatedForm.controls['enabled'].value,
      config
    });
  }

  private submitSmtp(): void {
    if (this.smtpForm.invalid) {
      this.smtpForm.markAllAsTouched();
      return;
    }

    const auth = this.smtpForm.controls.auth.value;
    const username = this.smtpForm.controls.username.value.trim();
    const password = this.smtpForm.controls.password.value.trim();
    if (auth === 'login' && (!username || !password)) {
      this.parseError.set('Username and password are required when auth=login.');
      return;
    }

    const port = Number.parseInt(this.smtpForm.controls.port.value, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      this.parseError.set('Port must be between 1 and 65535.');
      return;
    }

    const timeoutSeconds = Number.parseInt(this.smtpForm.controls.timeoutSeconds.value, 10);
    if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 60) {
      this.parseError.set('Timeout must be between 1 and 60 seconds.');
      return;
    }
    const repeatInterval = this.smtpForm.controls.repeatInterval.value.trim();
    if (repeatInterval && !this.isValidRepeatInterval(repeatInterval)) {
      this.parseError.set('Repeat interval must use Alertmanager duration format (for example 15m, 1h, 90m).');
      return;
    }

    const config: SmtpConnectorConfig = {
      host: this.smtpForm.controls.host.value.trim(),
      port,
      username,
      password,
      fromEmail: this.smtpForm.controls.fromEmail.value.trim(),
      fromName: this.smtpForm.controls.fromName.value.trim(),
      replyTo: this.smtpForm.controls.replyTo.value.trim(),
      domain: this.smtpForm.controls.domain.value.trim(),
      auth,
      encryption: this.smtpForm.controls.encryption.value,
      verifyMode: this.smtpForm.controls.verifyMode.value,
      timeoutSeconds,
      repeatInterval,
      sendResolved: this.smtpForm.controls.sendResolved.value,
      messageTemplate: this.smtpForm.controls.messageTemplate.value.trim()
    };
    const configPayload: Record<string, unknown> = { ...config };
    if (!config.repeatInterval) {
      delete configPayload['repeatInterval'];
    }
    if (!config.messageTemplate) {
      delete configPayload['messageTemplate'];
    }

    this.ref.close({
      enabled: this.smtpForm.controls.enabled.value,
      config: configPayload
    });
  }

  private submitSlack(): void {
    if (this.slackForm.invalid) {
      this.slackForm.markAllAsTouched();
      return;
    }

    const webhookUrl = this.slackForm.controls.webhookUrl.value.trim();
    const botToken = this.slackForm.controls.botToken.value.trim();
    if (!webhookUrl && !botToken) {
      this.parseError.set('Provide at least one credential: Webhook URL or Bot token.');
      return;
    }
    if (webhookUrl) {
      try {
        const parsed = new URL(webhookUrl);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
          this.parseError.set('Webhook URL must use http:// or https://.');
          return;
        }
      } catch {
        this.parseError.set('Webhook URL must be a valid URL.');
        return;
      }
    }
    const repeatInterval = this.slackForm.controls.repeatInterval.value.trim();
    if (repeatInterval && !this.isValidRepeatInterval(repeatInterval)) {
      this.parseError.set('Repeat interval must use Alertmanager duration format (for example 15m, 1h, 90m).');
      return;
    }

    const config: SlackConnectorConfig = {
      webhookUrl,
      botToken,
      defaultChannel: this.slackForm.controls.defaultChannel.value.trim(),
      username: this.slackForm.controls.username.value.trim(),
      repeatInterval,
      sendResolved: this.slackForm.controls.sendResolved.value,
      messageTemplate: this.slackForm.controls.messageTemplate.value.trim()
    };
    const configPayload: Record<string, unknown> = { ...config };
    if (!config.repeatInterval) {
      delete configPayload['repeatInterval'];
    }
    if (!config.messageTemplate) {
      delete configPayload['messageTemplate'];
    }

    this.ref.close({
      enabled: this.slackForm.controls.enabled.value,
      config: configPayload
    });
  }

  private parseConfig(raw: string): Record<string, unknown> | null {
    const trimmed = raw.trim();
    if (!trimmed) {
      return {};
    }
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      if (!isRecord(parsed)) {
        return null;
      }
      return parsed;
    } catch {
      return null;
    }
  }

  private prettyJson(value: Record<string, unknown>): string {
    try {
      return JSON.stringify(value ?? {}, null, 2);
    } catch {
      return '{}';
    }
  }

  private parseSmtpConfig(config: Record<string, unknown>): SmtpConnectorConfig {
    const readString = (value: unknown): string => {
      return typeof value === 'string' ? value : '';
    };
    const readNumber = (value: unknown, fallback: number): number => {
      if (typeof value === 'number' && Number.isFinite(value)) {
        return Math.floor(value);
      }
      if (typeof value === 'string') {
        const parsed = Number.parseInt(value, 10);
        if (Number.isInteger(parsed)) {
          return parsed;
        }
      }
      return fallback;
    };
    const readOneOf = <T extends string>(value: unknown, allowed: readonly T[], fallback: T): T => {
      const normalized = String(value ?? '').trim().toLowerCase();
      if (allowed.includes(normalized as T)) {
        return normalized as T;
      }
      return fallback;
    };

    const source = {
      host: config['host'],
      port: config['port'],
      username: config['username'],
      password: config['password'],
      fromEmail: config['fromEmail'] ?? config['from_email'],
      fromName: config['fromName'] ?? config['from_name'],
      replyTo: config['replyTo'] ?? config['reply_to'],
      domain: config['domain'],
      auth: config['auth'],
      encryption: config['encryption'],
      verifyMode: config['verifyMode'] ?? config['verify_mode'],
      timeoutSeconds: config['timeoutSeconds'] ?? config['timeout_seconds'],
      repeatInterval: config['repeatInterval'] ?? config['repeat_interval'],
      sendResolved: config['sendResolved'] ?? config['send_resolved'],
      messageTemplate: config['messageTemplate'] ?? config['message_template']
    };

    const rawPassword = readString(source.password);
    const password = rawPassword === '***' ? '' : rawPassword;

    return {
      host: readString(source.host),
      port: readNumber(source.port, 587),
      username: readString(source.username),
      password,
      fromEmail: readString(source.fromEmail),
      fromName: readString(source.fromName),
      replyTo: readString(source.replyTo),
      domain: readString(source.domain),
      auth: readOneOf(source.auth, ['login', 'none'], 'login'),
      encryption: readOneOf(source.encryption, ['starttls', 'tls', 'none'], 'starttls'),
      verifyMode: readOneOf(source.verifyMode, ['peer', 'none'], 'peer'),
      timeoutSeconds: readNumber(source.timeoutSeconds, 10),
      repeatInterval: readString(source.repeatInterval),
      sendResolved: this.readBooleanDefaultTrue(source.sendResolved),
      messageTemplate: readString(source.messageTemplate)
    };
  }

  private parseSlackConfig(config: Record<string, unknown>): SlackConnectorConfig {
    const readString = (value: unknown): string => {
      return typeof value === 'string' ? value : '';
    };
    const source = {
      webhookUrl: config['webhookUrl'] ?? config['webhook_url'] ?? config['api_url'],
      botToken: config['botToken'] ?? config['bot_token'],
      defaultChannel: config['defaultChannel'] ?? config['default_channel'] ?? config['channel'],
      username: config['username'],
      repeatInterval: config['repeatInterval'] ?? config['repeat_interval'],
      sendResolved: config['sendResolved'] ?? config['send_resolved'],
      messageTemplate: config['messageTemplate'] ?? config['message_template']
    };
    const rawToken = readString(source.botToken);
    return {
      webhookUrl: readString(source.webhookUrl),
      botToken: rawToken === '***' ? '' : rawToken,
      defaultChannel: readString(source.defaultChannel),
      username: readString(source.username),
      repeatInterval: readString(source.repeatInterval),
      sendResolved: this.readBooleanDefaultTrue(source.sendResolved),
      messageTemplate: readString(source.messageTemplate)
    };
  }

  private buildDedicatedForm() {
    const controls: Record<string, [string | boolean, ValidatorFn[]]> = {
      enabled: [this.data.connector.enabled, []]
    };
    for (const field of this.dedicatedFields) {
      if (field.type === 'boolean') {
        controls[field.control] = [this.readBooleanConfigValue(field), []];
        continue;
      }
      controls[field.control] = [this.readTextConfigValue(field), this.buildFieldValidators(field)];
    }
    return this.fb.group(controls);
  }

  private buildFieldValidators(field: DedicatedConnectorField): ValidatorFn[] {
    const validators: ValidatorFn[] = [];
    if (field.required) {
      validators.push(Validators.required);
    }
    if (typeof field.maxLength === 'number') {
      validators.push(Validators.maxLength(field.maxLength));
    }
    if (field.type === 'number') {
      validators.push(Validators.pattern('^[0-9]+$'));
    }
    return validators;
  }

  private readBooleanConfigValue(field: DedicatedConnectorField): boolean {
    const value = this.getNormalizedConfigValue(field.output);
    if (typeof value === 'boolean') {
      return value;
    }
    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();
      if (normalized === 'true' || normalized === '1') {
        return true;
      }
      if (normalized === 'false' || normalized === '0') {
        return false;
      }
    }
    return typeof field.defaultValue === 'boolean' ? field.defaultValue : false;
  }

  private readTextConfigValue(field: DedicatedConnectorField): string {
    const value = this.getNormalizedConfigValue(field.output);
    if (typeof value === 'string') {
      if (this.isPreservableSecretField(field.output) && value.trim() === '***') {
        return '';
      }
      return value;
    }
    if (this.connectorType === 'jira' && field.output === 'email') {
      const legacyUsername = this.getNormalizedConfigValue('username');
      if (typeof legacyUsername === 'string') {
        return legacyUsername;
      }
    }
    if (typeof value === 'number' && Number.isFinite(value)) {
      return String(value);
    }
    if (typeof field.defaultValue === 'string') {
      return field.defaultValue;
    }
    if (typeof field.defaultValue === 'number') {
      return String(field.defaultValue);
    }
    return '';
  }

  private isPreservableSecretField(output: string): boolean {
    const normalized = this.normalizeFieldKey(output);
    if (this.connectorType === 'jira') {
      return normalized === 'api_token' || normalized === 'password';
    }
    if (this.connectorType === 'alertmanager_external') {
      return normalized === 'token' || normalized === 'password';
    }
    return false;
  }

  private hasMaskedStoredSecret(output: string): boolean {
    const value = this.getNormalizedConfigValue(output);
    return typeof value === 'string' && value.trim() === '***';
  }

  private getNormalizedConfigValue(key: string): unknown {
    return this.normalizedConnectorConfig[this.normalizeFieldKey(key)];
  }

  private normalizeConfigKeys(input: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input ?? {})) {
      out[this.normalizeFieldKey(key)] = value;
    }
    return out;
  }

  private normalizeFieldKey(input: string): string {
    const trimmed = String(input ?? '').trim();
    if (!trimmed) {
      return '';
    }
    return trimmed
      .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
      .replace(/[\s-]+/g, '_')
      .toLowerCase();
  }

  private isHTTPURL(value: string): boolean {
    try {
      const parsed = new URL(value);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }

  private isValidRepeatInterval(value: string): boolean {
    return alertmanagerDurationPattern.test(value.trim());
  }

  private readBooleanDefaultTrue(value: unknown): boolean {
    if (typeof value === 'boolean') {
      return value;
    }
    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();
      if (normalized === 'true' || normalized === '1') {
        return true;
      }
      if (normalized === 'false' || normalized === '0') {
        return false;
      }
    }
    if (typeof value === 'number') {
      if (value === 0) {
        return false;
      }
      if (value === 1) {
        return true;
      }
    }
    return true;
  }
}
