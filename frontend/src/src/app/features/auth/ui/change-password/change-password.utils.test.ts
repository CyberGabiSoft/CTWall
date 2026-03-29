import { describe, expect, it } from 'vitest';
import { isStrongPassword } from './change-password.utils';

describe('isStrongPassword', () => {
  it('accepts strong passwords', () => {
    expect(isStrongPassword('Str0ng!Passw0rd')).toBe(true);
  });

  it('rejects weak passwords', () => {
    expect(isStrongPassword('short')).toBe(false);
    expect(isStrongPassword('alllowercase123!')).toBe(false);
    expect(isStrongPassword('ALLUPPERCASE123!')).toBe(false);
    expect(isStrongPassword('NoDigitsHere!')).toBe(false);
    expect(isStrongPassword('NoSpecials123')).toBe(false);
  });
});
