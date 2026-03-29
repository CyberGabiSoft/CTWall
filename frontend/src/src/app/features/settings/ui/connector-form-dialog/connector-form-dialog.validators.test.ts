import { describe, expect, it } from 'vitest';
import { validateDedicatedConnectorConfig } from './connector-form-dialog.validators';

describe('validateDedicatedConnectorConfig', () => {
  it('normalizes Jira api_token mode by copying username to email and removing basic fields', () => {
    const config: Record<string, unknown> = {
      auth_mode: 'api_token',
      deployment_mode: 'auto',
      base_url: 'https://example.atlassian.net',
      username: 'user@example.com',
      api_token: 'secret-token',
      password: 'legacy',
    };

    const error = validateDedicatedConnectorConfig('jira', config);

    expect(error).toBeNull();
    expect(config['email']).toBe('user@example.com');
    expect(config['username']).toBeUndefined();
    expect(config['password']).toBeUndefined();
  });

  it('returns Jira cloud validation error for basic auth mode', () => {
    const config: Record<string, unknown> = {
      auth_mode: 'basic',
      deployment_mode: 'cloud',
      base_url: 'https://example.atlassian.net',
      username: 'john',
      password: 'secret',
    };

    const error = validateDedicatedConnectorConfig('jira', config);

    expect(error).toContain('For Jira Cloud');
  });

  it('clears external alertmanager auth secrets for auth_mode=none', () => {
    const config: Record<string, unknown> = {
      auth_mode: 'none',
      username: 'u',
      password: 'p',
      token: 't',
    };

    const error = validateDedicatedConnectorConfig('alertmanager_external', config);

    expect(error).toBeNull();
    expect(config['username']).toBeUndefined();
    expect(config['password']).toBeUndefined();
    expect(config['token']).toBeUndefined();
  });
});
