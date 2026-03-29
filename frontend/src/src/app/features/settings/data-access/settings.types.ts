import { AccountType, UserRole } from '../../auth/auth.types';

export interface SettingsGeneralResponse {
  readOnly: boolean;
  configPath: string;
  generatedAt: string;
  config: Record<string, unknown>;
  sources: Record<string, string>;
}

export type ConnectorTestStatus = 'NOT_CONFIGURED' | 'PASSED' | 'FAILED';

export interface AdminConnector {
  id?: string;
  type: string;
  scopeType: string;
  scopeId?: string;
  enabled: boolean;
  configured: boolean;
  config: Record<string, unknown>;
  lastTestStatus: ConnectorTestStatus;
  lastTestAt?: string;
  lastTestMessage?: string;
  updatedAt?: string;
}

export interface ConnectorUpsertRequest {
  enabled: boolean;
  config: Record<string, unknown>;
}

export interface ConnectorTestRequest {
  toEmail?: string;
}

export interface ConnectorTestResponse {
  type: string;
  status: ConnectorTestStatus;
  message: string;
  testedAt: string;
}

export type SmtpAuthMode = 'login' | 'none';
export type SmtpEncryptionMode = 'starttls' | 'tls' | 'none';
export type SmtpVerifyMode = 'peer' | 'none';

export interface SmtpConnectorConfig {
  host: string;
  port: number;
  username: string;
  password: string;
  fromEmail: string;
  fromName: string;
  replyTo: string;
  domain: string;
  auth: SmtpAuthMode;
  encryption: SmtpEncryptionMode;
  verifyMode: SmtpVerifyMode;
  timeoutSeconds: number;
  repeatInterval: string;
  sendResolved: boolean;
  messageTemplate: string;
}

export interface SlackConnectorConfig {
  webhookUrl: string;
  botToken: string;
  defaultChannel: string;
  username: string;
  repeatInterval: string;
  sendResolved: boolean;
  messageTemplate: string;
}

export interface SettingsUser {
  id: string;
  email: string;
  nickname: string;
  role: UserRole;
  accountType: AccountType;
  fullName?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateUserRequest {
  email: string;
  password: string;
  role: UserRole;
  accountType: AccountType;
  nickname: string;
  fullName?: string;
}

export interface UpdateUserRequest {
  role: UserRole;
  accountType: AccountType;
  nickname: string;
  fullName?: string;
}

export interface ResetUserPasswordRequest {
  newPassword: string;
}

export interface CreateUserTokenRequest {
  name?: string;
  expiresAt?: string;
}

export interface CreateUserTokenResponse {
  tokenId: string;
  token: string;
  name: string;
  expiresAt?: string;
  createdAt: string;
}
