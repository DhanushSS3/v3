-- CreateEnum
CREATE TYPE "AdminRole" AS ENUM ('super_admin', 'admin', 'support', 'compliance', 'finance');

-- CreateEnum
CREATE TYPE "AudienceType" AS ENUM ('all', 'live', 'demo', 'mam_manager', 'strategy_provider', 'specific_group', 'specific_country');

-- CreateEnum
CREATE TYPE "AnnouncementType" AS ENUM ('maintenance', 'feature_update', 'market_alert', 'regulatory', 'deposit_withdrawal', 'version_update', 'general');

-- CreateEnum
CREATE TYPE "AnnouncementPriority" AS ENUM ('low', 'medium', 'high', 'critical');

-- CreateTable
CREATE TABLE "admin_users" (
    "id" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "role" "AdminRole" NOT NULL DEFAULT 'support',
    "permissions" TEXT[],
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "lastLoginAt" TIMESTAMPTZ,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ NOT NULL,

    CONSTRAINT "admin_users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_logs" (
    "id" BIGSERIAL NOT NULL,
    "adminId" UUID NOT NULL,
    "action" TEXT NOT NULL,
    "targetType" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "beforeState" JSONB,
    "afterState" JSONB,
    "ipAddress" TEXT,
    "performedAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "announcements" (
    "id" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "summary" TEXT,
    "announcementType" "AnnouncementType" NOT NULL DEFAULT 'general',
    "priority" "AnnouncementPriority" NOT NULL DEFAULT 'medium',
    "audience" "AudienceType" NOT NULL DEFAULT 'all',
    "targetGroups" TEXT[],
    "targetCountries" TEXT[],
    "deliveryChannels" TEXT[],
    "isPublished" BOOLEAN NOT NULL DEFAULT false,
    "scheduledAt" TIMESTAMPTZ,
    "publishedAt" TIMESTAMPTZ,
    "expiresAt" TIMESTAMPTZ,
    "requiresAck" BOOLEAN NOT NULL DEFAULT false,
    "ctaUrl" TEXT,
    "ctaLabel" TEXT,
    "kafkaEventId" TEXT,
    "createdBy" UUID NOT NULL,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ NOT NULL,

    CONSTRAINT "announcements_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "announcement_translations" (
    "id" UUID NOT NULL,
    "announcementId" UUID NOT NULL,
    "locale" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "summary" TEXT,
    "ctaLabel" TEXT,

    CONSTRAINT "announcement_translations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "announcement_user_acks" (
    "id" UUID NOT NULL,
    "announcementId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userType" TEXT NOT NULL,
    "ackedAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ipAddress" TEXT,
    "deviceId" TEXT,

    CONSTRAINT "announcement_user_acks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "system_config" (
    "key" TEXT NOT NULL,
    "value" JSONB NOT NULL,
    "description" TEXT,
    "updatedBy" UUID,
    "updatedAt" TIMESTAMPTZ NOT NULL,

    CONSTRAINT "system_config_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "roles" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,

    CONSTRAINT "roles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "permissions" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,

    CONSTRAINT "permissions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "role_permissions" (
    "roleId" UUID NOT NULL,
    "permissionId" UUID NOT NULL,

    CONSTRAINT "role_permissions_pkey" PRIMARY KEY ("roleId","permissionId")
);

-- CreateTable
CREATE TABLE "admin_role_assignments" (
    "adminId" UUID NOT NULL,
    "roleId" UUID NOT NULL,

    CONSTRAINT "admin_role_assignments_pkey" PRIMARY KEY ("adminId","roleId")
);

-- CreateIndex
CREATE UNIQUE INDEX "admin_users_email_key" ON "admin_users"("email");

-- CreateIndex
CREATE INDEX "audit_logs_adminId_performedAt_idx" ON "audit_logs"("adminId", "performedAt");

-- CreateIndex
CREATE INDEX "audit_logs_targetType_targetId_performedAt_idx" ON "audit_logs"("targetType", "targetId", "performedAt");

-- CreateIndex
CREATE INDEX "audit_logs_action_performedAt_idx" ON "audit_logs"("action", "performedAt");

-- CreateIndex
CREATE UNIQUE INDEX "announcements_kafkaEventId_key" ON "announcements"("kafkaEventId");

-- CreateIndex
CREATE INDEX "announcements_isPublished_audience_scheduledAt_expiresAt_idx" ON "announcements"("isPublished", "audience", "scheduledAt", "expiresAt");

-- CreateIndex
CREATE INDEX "announcements_announcementType_priority_createdAt_idx" ON "announcements"("announcementType", "priority", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "announcement_translations_announcementId_locale_key" ON "announcement_translations"("announcementId", "locale");

-- CreateIndex
CREATE INDEX "announcement_user_acks_announcementId_idx" ON "announcement_user_acks"("announcementId");

-- CreateIndex
CREATE INDEX "announcement_user_acks_userId_userType_idx" ON "announcement_user_acks"("userId", "userType");

-- CreateIndex
CREATE UNIQUE INDEX "announcement_user_acks_announcementId_userId_userType_key" ON "announcement_user_acks"("announcementId", "userId", "userType");

-- CreateIndex
CREATE UNIQUE INDEX "roles_name_key" ON "roles"("name");

-- CreateIndex
CREATE UNIQUE INDEX "permissions_name_key" ON "permissions"("name");

-- AddForeignKey
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "admin_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "announcements" ADD CONSTRAINT "announcements_createdBy_fkey" FOREIGN KEY ("createdBy") REFERENCES "admin_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "announcement_translations" ADD CONSTRAINT "announcement_translations_announcementId_fkey" FOREIGN KEY ("announcementId") REFERENCES "announcements"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "announcement_user_acks" ADD CONSTRAINT "announcement_user_acks_announcementId_fkey" FOREIGN KEY ("announcementId") REFERENCES "announcements"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "system_config" ADD CONSTRAINT "system_config_updatedBy_fkey" FOREIGN KEY ("updatedBy") REFERENCES "admin_users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "roles"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_permissionId_fkey" FOREIGN KEY ("permissionId") REFERENCES "permissions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "admin_role_assignments" ADD CONSTRAINT "admin_role_assignments_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "admin_users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "admin_role_assignments" ADD CONSTRAINT "admin_role_assignments_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "roles"("id") ON DELETE CASCADE ON UPDATE CASCADE;
