-- CreateEnum
CREATE TYPE "UserType" AS ENUM ('live', 'demo', 'mam_manager', 'strategy_provider', 'admin');

-- CreateEnum
CREATE TYPE "OtpPurpose" AS ENUM ('login', 'forgot_password', 'email_verify', 'phone_verify', 'withdrawal_confirm', 'twofa_setup');

-- CreateTable
CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userType" "UserType" NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "refreshHash" TEXT,
    "issuedAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMPTZ NOT NULL,
    "revokedAt" TIMESTAMPTZ,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "deviceId" TEXT,
    "fingerprintHash" TEXT,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "known_devices" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userType" "UserType" NOT NULL,
    "fingerprintHash" TEXT NOT NULL,
    "label" TEXT,
    "firstSeenAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "known_devices_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "api_keys" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userType" "UserType" NOT NULL,
    "keyHash" TEXT NOT NULL,
    "label" TEXT,
    "permissions" TEXT[],
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMPTZ,
    "lastUsedAt" TIMESTAMPTZ,
    "revokedAt" TIMESTAMPTZ,

    CONSTRAINT "api_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "api_key_ip_whitelist" (
    "id" UUID NOT NULL,
    "apiKeyId" UUID NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "label" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "addedBy" UUID,
    "expiresAt" TIMESTAMPTZ,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "api_key_ip_whitelist_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "otp_attempts" (
    "id" BIGSERIAL NOT NULL,
    "identifier" TEXT NOT NULL,
    "purpose" "OtpPurpose" NOT NULL,
    "otpHash" TEXT NOT NULL,
    "attempts" SMALLINT NOT NULL DEFAULT 0,
    "verifiedAt" TIMESTAMPTZ,
    "expiresAt" TIMESTAMPTZ NOT NULL,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "otp_attempts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "password_reset_tokens" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userType" "UserType" NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMPTZ NOT NULL,
    "usedAt" TIMESTAMPTZ,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "password_reset_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_totp_secrets" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userType" "UserType" NOT NULL,
    "secretEnc" TEXT NOT NULL,
    "isVerified" BOOLEAN NOT NULL DEFAULT false,
    "enabledAt" TIMESTAMPTZ,
    "disabledAt" TIMESTAMPTZ,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_totp_secrets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "trusted_devices" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userType" "UserType" NOT NULL,
    "fingerprintHash" TEXT NOT NULL,
    "label" TEXT,
    "trustedUntil" TIMESTAMPTZ NOT NULL,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "trusted_devices_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "sessions_tokenHash_key" ON "sessions"("tokenHash");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_refreshHash_key" ON "sessions"("refreshHash");

-- CreateIndex
CREATE INDEX "sessions_userId_userType_idx" ON "sessions"("userId", "userType");

-- CreateIndex
CREATE INDEX "sessions_expiresAt_idx" ON "sessions"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "known_devices_userId_userType_fingerprintHash_key" ON "known_devices"("userId", "userType", "fingerprintHash");

-- CreateIndex
CREATE UNIQUE INDEX "api_keys_keyHash_key" ON "api_keys"("keyHash");

-- CreateIndex
CREATE INDEX "api_keys_userId_userType_idx" ON "api_keys"("userId", "userType");

-- CreateIndex
CREATE INDEX "api_key_ip_whitelist_apiKeyId_idx" ON "api_key_ip_whitelist"("apiKeyId");

-- CreateIndex
CREATE UNIQUE INDEX "api_key_ip_whitelist_apiKeyId_ipAddress_key" ON "api_key_ip_whitelist"("apiKeyId", "ipAddress");

-- CreateIndex
CREATE INDEX "otp_attempts_identifier_purpose_expiresAt_idx" ON "otp_attempts"("identifier", "purpose", "expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "password_reset_tokens_tokenHash_key" ON "password_reset_tokens"("tokenHash");

-- CreateIndex
CREATE INDEX "password_reset_tokens_tokenHash_idx" ON "password_reset_tokens"("tokenHash");

-- CreateIndex
CREATE UNIQUE INDEX "user_totp_secrets_userId_userType_key" ON "user_totp_secrets"("userId", "userType");

-- CreateIndex
CREATE INDEX "trusted_devices_userId_fingerprintHash_trustedUntil_idx" ON "trusted_devices"("userId", "fingerprintHash", "trustedUntil");

-- CreateIndex
CREATE UNIQUE INDEX "trusted_devices_userId_userType_fingerprintHash_key" ON "trusted_devices"("userId", "userType", "fingerprintHash");

-- AddForeignKey
ALTER TABLE "api_key_ip_whitelist" ADD CONSTRAINT "api_key_ip_whitelist_apiKeyId_fkey" FOREIGN KEY ("apiKeyId") REFERENCES "api_keys"("id") ON DELETE CASCADE ON UPDATE CASCADE;
