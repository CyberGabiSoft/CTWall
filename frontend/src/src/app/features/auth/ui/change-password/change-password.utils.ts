export const passwordRequirements = {
  minLength: 12
};

const countRunes = (value: string): number => Array.from(value).length;

export const isStrongPassword = (value: string, minLength = passwordRequirements.minLength): boolean => {
  if (countRunes(value) < minLength) {
    return false;
  }
  const hasLower = /[a-z]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  const hasDigit = /\d/.test(value);
  const hasSpecial = /[^A-Za-z0-9]/.test(value);
  return hasLower && hasUpper && hasDigit && hasSpecial;
};
