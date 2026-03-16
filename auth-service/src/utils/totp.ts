import speakeasy from 'speakeasy';
import { encryptAES, decryptAES } from './hash';
import { config } from '../config/env';

export interface TotpSetup {
  secretEnc: string;
  otpauthUrl: string;
}

export function generateTotpSetup(accountLabel: string): TotpSetup {
  const secret = speakeasy.generateSecret({
    name: `LiveFXHub (${accountLabel})`,
    length: 20,
  });
  const secretEnc = encryptAES(secret.base32!, config.totpEncryptionKey);
  return { secretEnc, otpauthUrl: secret.otpauth_url! };
}

export function verifyTotpCode(secretEnc: string, token: string): boolean {
  const base32 = decryptAES(secretEnc, config.totpEncryptionKey);
  return speakeasy.totp.verify({
    secret: base32,
    encoding: 'base32',
    token,
    window: 1, // Allow 1 step drift (30s tolerance)
  });
}
