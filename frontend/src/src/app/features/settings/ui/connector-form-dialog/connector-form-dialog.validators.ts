export const validateDedicatedConnectorConfig = (
  connectorType: string,
  config: Record<string, unknown>,
): string | null => {
  if (connectorType === 'jira') {
    return validateJiraDedicatedConfig(config);
  }
  if (connectorType === 'alertmanager_external') {
    return validateExternalAlertmanagerDedicatedConfig(config);
  }
  return null;
};

const validateJiraDedicatedConfig = (config: Record<string, unknown>): string | null => {
  const read = (
    key:
      | 'base_url'
      | 'auth_mode'
      | 'deployment_mode'
      | 'email'
      | 'api_token'
      | 'username'
      | 'password',
  ): string => {
    switch (key) {
      case 'base_url':
        return String(config['base_url'] ?? '').trim();
      case 'auth_mode':
        return String(config['auth_mode'] ?? '').trim();
      case 'deployment_mode':
        return String(config['deployment_mode'] ?? '').trim();
      case 'email':
        return String(config['email'] ?? '').trim();
      case 'api_token':
        return String(config['api_token'] ?? '').trim();
      case 'username':
        return String(config['username'] ?? '').trim();
      case 'password':
        return String(config['password'] ?? '').trim();
    }
  };

  const authMode = read('auth_mode').toLowerCase();
  const deploymentMode = read('deployment_mode').toLowerCase();

  if (
    deploymentMode !== 'auto' &&
    deploymentMode !== 'cloud' &&
    deploymentMode !== 'datacenter'
  ) {
    return 'Deployment mode must be one of: auto, cloud, datacenter.';
  }
  if (authMode !== 'api_token' && authMode !== 'basic') {
    return 'Auth mode must be one of: api_token, basic.';
  }

  if (authMode === 'api_token') {
    const email = read('email');
    const usernameFallback = read('username');
    if (!email && usernameFallback) {
      config['email'] = usernameFallback;
    }
    if (!String(config['email'] ?? '').trim()) {
      return 'Email is required for auth mode api_token.';
    }
    if (!read('api_token')) {
      return 'API token is required for auth mode api_token.';
    }
    delete config['username'];
    delete config['password'];
    return null;
  }

  if (!read('username')) {
    const emailFallback = read('email');
    if (emailFallback) {
      config['username'] = emailFallback;
    }
  }

  const baseURL = read('base_url').toLowerCase();
  if (baseURL.includes('.atlassian.net')) {
    return 'For Jira Cloud (.atlassian.net), use auth mode "API token (Cloud)" instead of basic password login.';
  }
  if (!String(config['username'] ?? '').trim()) {
    return 'Username is required for auth mode basic.';
  }
  if (!read('password')) {
    return 'Password is required for auth mode basic.';
  }
  delete config['email'];
  delete config['api_token'];
  return null;
};

const validateExternalAlertmanagerDedicatedConfig = (
  config: Record<string, unknown>,
): string | null => {
  const authMode = String(config['auth_mode'] ?? '')
    .trim()
    .toLowerCase();
  if (authMode !== 'none' && authMode !== 'basic' && authMode !== 'bearer') {
    return 'Auth mode must be one of: none, basic, bearer.';
  }
  if (authMode === 'none') {
    delete config['username'];
    delete config['password'];
    delete config['token'];
    return null;
  }
  if (authMode === 'basic') {
    const username = String(config['username'] ?? '').trim();
    const password = String(config['password'] ?? '').trim();
    if (!username) {
      return 'Username is required for auth mode basic.';
    }
    if (!password) {
      return 'Password is required for auth mode basic.';
    }
    delete config['token'];
    return null;
  }
  const token = String(config['token'] ?? '').trim();
  if (!token) {
    return 'Bearer token is required for auth mode bearer.';
  }
  delete config['username'];
  delete config['password'];
  return null;
};
