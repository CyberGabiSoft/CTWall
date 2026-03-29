export type UserRole = 'ADMIN' | 'WRITER' | 'READER' | 'NONE';
export type AccountType = 'USER' | 'SERVICE_ACCOUNT';

export interface AuthUser {
  id: string;
  email: string;
  nickname: string;
  role: UserRole;
  accountType: AccountType;
  fullName?: string;
}

export type AuthStatus = 'unknown' | 'authenticated' | 'anonymous';
