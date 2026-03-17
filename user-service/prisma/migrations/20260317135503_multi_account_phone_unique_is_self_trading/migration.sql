-- CreateEnum
CREATE TYPE "KycStatus" AS ENUM ('pending', 'submitted', 'approved', 'rejected');

-- CreateEnum
CREATE TYPE "AllocationMethod" AS ENUM ('balance', 'free_margin', 'equity', 'lot');

-- CreateEnum
CREATE TYPE "RoundingStrategy" AS ENUM ('symbol_step', 'floor', 'ceil');

-- CreateEnum
CREATE TYPE "StrategyVisibility" AS ENUM ('public', 'private');

-- CreateEnum
CREATE TYPE "CommissionType" AS ENUM ('per_lot', 'per_trade', 'percent');

-- CreateEnum
CREATE TYPE "CommissionValueType" AS ENUM ('money', 'percent', 'pips');

-- CreateEnum
CREATE TYPE "SwapType" AS ENUM ('pips', 'percent', 'currency');

-- CreateEnum
CREATE TYPE "MarginCalcMode" AS ENUM ('standard', 'crypto', 'cfd_index', 'fixed');

-- CreateEnum
CREATE TYPE "BonusCampaignType" AS ENUM ('deposit_tiered', 'flat_deposit', 'no_deposit', 'referral');

-- CreateEnum
CREATE TYPE "BonusType" AS ENUM ('percent', 'fixed');

-- CreateEnum
CREATE TYPE "UserBonusStatus" AS ENUM ('active', 'unlocked', 'withdrawn', 'forfeited', 'expired');

-- CreateEnum
CREATE TYPE "TransactionType" AS ENUM ('deposit', 'withdrawal', 'bonus', 'adjustment', 'fee', 'transfer');

-- CreateEnum
CREATE TYPE "TransactionStatus" AS ENUM ('pending', 'approved', 'rejected', 'processing', 'completed');

-- CreateTable
CREATE TABLE "live_users" (
    "id" UUID NOT NULL,
    "externalId" TEXT,
    "accountNumber" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "phone" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "countryCode" TEXT,
    "kycStatus" "KycStatus" NOT NULL DEFAULT 'pending',
    "groupId" UUID,
    "groupName" TEXT NOT NULL DEFAULT 'Standard',
    "leverage" SMALLINT NOT NULL DEFAULT 100,
    "currency" TEXT NOT NULL DEFAULT 'USD',
    "isSelfTrading" BOOLEAN NOT NULL DEFAULT true,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "isVerified" BOOLEAN NOT NULL DEFAULT false,
    "referralCode" TEXT,
    "referredBy" UUID,
    "securityQuestion" TEXT,
    "securityAnswerHash" TEXT,
    "lastLoginAt" TIMESTAMPTZ,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ NOT NULL,
    "deletedAt" TIMESTAMPTZ,

    CONSTRAINT "live_users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "demo_users" (
    "id" UUID NOT NULL,
    "accountNumber" TEXT NOT NULL,
    "email" TEXT,
    "phone" TEXT,
    "passwordHash" TEXT NOT NULL,
    "fullName" TEXT,
    "groupName" TEXT NOT NULL DEFAULT 'Standard',
    "leverage" SMALLINT NOT NULL DEFAULT 100,
    "currency" TEXT NOT NULL DEFAULT 'USD',
    "demoBalance" DECIMAL(18,6) NOT NULL DEFAULT 10000.00,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "lastLoginAt" TIMESTAMPTZ,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ NOT NULL,

    CONSTRAINT "demo_users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "live_user_kyc" (
    "userId" UUID NOT NULL,
    "addressLine1" TEXT,
    "addressLine2" TEXT,
    "city" TEXT,
    "state" TEXT,
    "country" TEXT,
    "pincode" TEXT,
    "bankName" TEXT,
    "bankIfscCode" TEXT,
    "bankAccountNumber" TEXT,
    "bankHolderName" TEXT,
    "idProofType" TEXT,
    "idProofPath" TEXT,
    "idProofBackPath" TEXT,
    "addressProofType" TEXT,
    "addressProofPath" TEXT,
    "selfiePath" TEXT,
    "reviewedBy" UUID,
    "reviewedAt" TIMESTAMPTZ,
    "rejectionReason" TEXT,
    "submittedAt" TIMESTAMPTZ,
    "updatedAt" TIMESTAMPTZ NOT NULL,

    CONSTRAINT "live_user_kyc_pkey" PRIMARY KEY ("userId")
);

-- CreateTable
CREATE TABLE "user_trading_config" (
    "userId" UUID NOT NULL,
    "manualTradingEnabled" BOOLEAN NOT NULL DEFAULT true,
    "algoTradingEnabled" BOOLEAN NOT NULL DEFAULT false,
    "copyTradingEnabled" BOOLEAN NOT NULL DEFAULT false,
    "mamEnabled" BOOLEAN NOT NULL DEFAULT false,
    "pamEnabled" BOOLEAN NOT NULL DEFAULT false,
    "activeMamAccountId" UUID,
    "activePamAccountId" UUID,
    "activeStrategyId" UUID,
    "copyRatio" DECIMAL(6,4),
    "viewPasswordHash" TEXT,
    "book" VARCHAR(5),
    "updatedAt" TIMESTAMPTZ NOT NULL,

    CONSTRAINT "user_trading_config_pkey" PRIMARY KEY ("userId")
);

-- CreateTable
CREATE TABLE "user_lp_assignment" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userType" TEXT NOT NULL,
    "lpProviderName" TEXT NOT NULL,
    "routingMode" TEXT NOT NULL DEFAULT 'external_lp',
    "orderTypes" TEXT[],
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "effectiveFrom" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "effectiveUntil" TIMESTAMPTZ,
    "assignedBy" UUID,
    "notes" TEXT,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_lp_assignment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mam_accounts" (
    "id" UUID NOT NULL,
    "managerUserId" UUID NOT NULL,
    "accountName" TEXT NOT NULL,
    "allocationMethod" "AllocationMethod" NOT NULL DEFAULT 'balance',
    "roundingStrategy" "RoundingStrategy" NOT NULL DEFAULT 'symbol_step',
    "performanceFeePct" DECIMAL(5,2) NOT NULL DEFAULT 0,
    "managementFeePct" DECIMAL(5,2) NOT NULL DEFAULT 0,
    "minDeposit" DECIMAL(18,6) NOT NULL DEFAULT 0,
    "autoCutoffLevel" DECIMAL(5,2) NOT NULL DEFAULT 50.00,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "isPublic" BOOLEAN NOT NULL DEFAULT false,
    "description" TEXT,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ NOT NULL,

    CONSTRAINT "mam_accounts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mam_investors" (
    "id" UUID NOT NULL,
    "mamAccountId" UUID NOT NULL,
    "investorUserId" UUID NOT NULL,
    "investedAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "removedAt" TIMESTAMPTZ,
    "initialBalance" DECIMAL(18,6) NOT NULL,

    CONSTRAINT "mam_investors_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "strategy_providers" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "accountNumber" TEXT NOT NULL,
    "strategyName" TEXT NOT NULL,
    "description" TEXT,
    "groupName" TEXT NOT NULL DEFAULT 'Standard',
    "leverage" SMALLINT NOT NULL DEFAULT 100,
    "visibility" "StrategyVisibility" NOT NULL DEFAULT 'public',
    "accessToken" TEXT,
    "performanceFeePct" DECIMAL(5,2) NOT NULL DEFAULT 20.00,
    "maxLeverage" SMALLINT NOT NULL DEFAULT 100,
    "minInvestment" DECIMAL(18,6) NOT NULL DEFAULT 100.00,
    "maxTotalInvestment" DECIMAL(18,6) NOT NULL DEFAULT 500000.00,
    "maxFollowers" INTEGER NOT NULL DEFAULT 1000,
    "autoCutoffLevel" DECIMAL(5,2) NOT NULL DEFAULT 50.00,
    "isCatalogEligible" BOOLEAN NOT NULL DEFAULT false,
    "isTrustworthy" BOOLEAN NOT NULL DEFAULT false,
    "catalogFreePass" BOOLEAN NOT NULL DEFAULT false,
    "firstTradeDate" TIMESTAMPTZ,
    "lastTradeDate" TIMESTAMPTZ,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "isArchived" BOOLEAN NOT NULL DEFAULT false,
    "archivedAt" TIMESTAMPTZ,
    "profileImageUrl" TEXT,
    "lastLoginAt" TIMESTAMPTZ,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ NOT NULL,

    CONSTRAINT "strategy_providers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "strategy_provider_stats" (
    "strategyId" UUID NOT NULL,
    "totalFollowers" INTEGER NOT NULL DEFAULT 0,
    "totalFollowerInvestment" DECIMAL(18,6) NOT NULL DEFAULT 0,
    "providerOwnInvestment" DECIMAL(18,6) NOT NULL DEFAULT 0,
    "totalTrades" INTEGER NOT NULL DEFAULT 0,
    "closedTrades" INTEGER NOT NULL DEFAULT 0,
    "winningTrades" INTEGER NOT NULL DEFAULT 0,
    "winRatePct" DECIMAL(5,2) NOT NULL DEFAULT 0,
    "totalReturnPct" DECIMAL(8,4) NOT NULL DEFAULT 0,
    "threeMonthReturnPct" DECIMAL(8,4) NOT NULL DEFAULT 0,
    "maxDrawdownPct" DECIMAL(8,4) NOT NULL DEFAULT 0,
    "sharpeRatio" DECIMAL(8,4),
    "avgTradeDurationSec" INTEGER,
    "lastComputedAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "strategy_provider_stats_pkey" PRIMARY KEY ("strategyId")
);

-- CreateTable
CREATE TABLE "copy_followers" (
    "id" UUID NOT NULL,
    "strategyId" UUID NOT NULL,
    "followerUserId" UUID NOT NULL,
    "copyRatio" DECIMAL(6,4) NOT NULL DEFAULT 1.0,
    "maxLotPerTrade" DECIMAL(12,4),
    "investedAmount" DECIMAL(18,6) NOT NULL DEFAULT 0,
    "copySLMode" VARCHAR(20) NOT NULL DEFAULT 'none',
    "slPercentage" DECIMAL(5,2),
    "slAmount" DECIMAL(18,6),
    "copyTPMode" VARCHAR(20) NOT NULL DEFAULT 'none',
    "tpPercentage" DECIMAL(5,2),
    "tpAmount" DECIMAL(18,6),
    "stopCopyingOnDrawdownPct" DECIMAL(5,2),
    "maxDailyLoss" DECIMAL(18,6),
    "copyStatus" VARCHAR(20) NOT NULL DEFAULT 'active',
    "pauseReason" TEXT,
    "stopReason" TEXT,
    "lastCopyAt" TIMESTAMPTZ,
    "startedAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "stoppedAt" TIMESTAMPTZ,

    CONSTRAINT "copy_followers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "groups" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "accountVariant" VARCHAR(20) NOT NULL DEFAULT 'standard',
    "displayMultiplier" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ NOT NULL,

    CONSTRAINT "groups_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "group_symbols" (
    "id" UUID NOT NULL,
    "groupId" UUID NOT NULL,
    "symbol" TEXT NOT NULL,
    "spreadType" VARCHAR(20) NOT NULL DEFAULT 'variable',
    "spread" DECIMAL(10,5) NOT NULL DEFAULT 0,
    "spreadPip" DECIMAL(10,5) NOT NULL DEFAULT 1,
    "maxSpread" DECIMAL(10,5),
    "swapBuy" DECIMAL(10,4) NOT NULL DEFAULT 0,
    "swapSell" DECIMAL(10,4) NOT NULL DEFAULT 0,
    "swapType" "SwapType" NOT NULL DEFAULT 'pips',
    "commission" DECIMAL(10,5) NOT NULL DEFAULT 0,
    "commissionType" "CommissionType" NOT NULL DEFAULT 'per_lot',
    "commissionValueType" "CommissionValueType" NOT NULL DEFAULT 'money',
    "marginPct" DECIMAL(8,4) NOT NULL DEFAULT 1,
    "marginCalcMode" "MarginCalcMode" NOT NULL DEFAULT 'standard',
    "marginFactor" DECIMAL(10,6) NOT NULL DEFAULT 1.0,
    "minLot" DECIMAL(12,4) NOT NULL DEFAULT 0.01,
    "maxLot" DECIMAL(12,4) NOT NULL DEFAULT 100,
    "lotStep" DECIMAL(12,4) NOT NULL DEFAULT 0.01,
    "contractSize" DECIMAL(18,4) NOT NULL DEFAULT 100000,
    "profitCurrency" TEXT NOT NULL DEFAULT 'USD',
    "pipCurrency" TEXT,
    "pips" DECIMAL(10,4) NOT NULL DEFAULT 0.0001,
    "showPoints" SMALLINT NOT NULL DEFAULT 5,
    "instrumentType" SMALLINT NOT NULL DEFAULT 0,
    "deviation" DECIMAL(10,4) NOT NULL DEFAULT 0,
    "bonus" DECIMAL(10,4) NOT NULL DEFAULT 0,
    "isTradable" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "group_symbols_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "market_sessions" (
    "id" UUID NOT NULL,
    "symbol" TEXT NOT NULL,
    "dayOfWeek" SMALLINT NOT NULL,
    "openTime" TEXT NOT NULL,
    "closeTime" TEXT NOT NULL,
    "timezone" TEXT NOT NULL DEFAULT 'UTC',
    "isActive" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "market_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "market_holidays" (
    "id" UUID NOT NULL,
    "symbol" TEXT,
    "holidayDate" DATE NOT NULL,
    "description" TEXT,

    CONSTRAINT "market_holidays_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_transactions" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userType" TEXT NOT NULL,
    "txnType" "TransactionType" NOT NULL,
    "amount" DECIMAL(18,6) NOT NULL,
    "currency" TEXT NOT NULL DEFAULT 'USD',
    "status" "TransactionStatus" NOT NULL DEFAULT 'pending',
    "gateway" TEXT,
    "gatewayTxnId" TEXT,
    "notes" TEXT,
    "processedBy" UUID,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ NOT NULL,

    CONSTRAINT "user_transactions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "bonus_campaigns" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "campaignType" "BonusCampaignType" NOT NULL DEFAULT 'deposit_tiered',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "startsAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endsAt" TIMESTAMPTZ,
    "createdBy" UUID,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "bonus_campaigns_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "bonus_campaign_tiers" (
    "id" UUID NOT NULL,
    "campaignId" UUID NOT NULL,
    "minDeposit" DECIMAL(18,6) NOT NULL,
    "maxDeposit" DECIMAL(18,6),
    "bonusType" "BonusType" NOT NULL DEFAULT 'percent',
    "bonusValue" DECIMAL(8,4) NOT NULL,
    "minLotsToUnlock" DECIMAL(12,4) NOT NULL DEFAULT 0,
    "withdrawalUnlockPct" DECIMAL(5,2) NOT NULL DEFAULT 20.0,
    "maxBonusCap" DECIMAL(18,6),
    "sortOrder" SMALLINT NOT NULL DEFAULT 0,

    CONSTRAINT "bonus_campaign_tiers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_bonus_allocations" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userType" TEXT NOT NULL,
    "campaignId" UUID NOT NULL,
    "tierId" UUID,
    "depositAmount" DECIMAL(18,6) NOT NULL,
    "bonusAmount" DECIMAL(18,6) NOT NULL,
    "lotsRequired" DECIMAL(12,4) NOT NULL DEFAULT 0,
    "lotsTraded" DECIMAL(12,4) NOT NULL DEFAULT 0,
    "status" "UserBonusStatus" NOT NULL DEFAULT 'active',
    "creditedAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "unlockedAt" TIMESTAMPTZ,
    "expiresAt" TIMESTAMPTZ,
    "triggeringTxnId" UUID,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ NOT NULL,

    CONSTRAINT "user_bonus_allocations_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "live_users_externalId_key" ON "live_users"("externalId");

-- CreateIndex
CREATE UNIQUE INDEX "live_users_accountNumber_key" ON "live_users"("accountNumber");

-- CreateIndex
CREATE UNIQUE INDEX "live_users_phone_key" ON "live_users"("phone");

-- CreateIndex
CREATE UNIQUE INDEX "live_users_referralCode_key" ON "live_users"("referralCode");

-- CreateIndex
CREATE INDEX "live_users_email_idx" ON "live_users"("email");

-- CreateIndex
CREATE INDEX "live_users_groupName_idx" ON "live_users"("groupName");

-- CreateIndex
CREATE INDEX "live_users_isActive_kycStatus_idx" ON "live_users"("isActive", "kycStatus");

-- CreateIndex
CREATE INDEX "live_users_accountNumber_idx" ON "live_users"("accountNumber");

-- CreateIndex
CREATE UNIQUE INDEX "demo_users_accountNumber_key" ON "demo_users"("accountNumber");

-- CreateIndex
CREATE UNIQUE INDEX "demo_users_phone_key" ON "demo_users"("phone");

-- CreateIndex
CREATE INDEX "user_lp_assignment_userId_userType_idx" ON "user_lp_assignment"("userId", "userType");

-- CreateIndex
CREATE INDEX "user_lp_assignment_lpProviderName_idx" ON "user_lp_assignment"("lpProviderName");

-- CreateIndex
CREATE INDEX "mam_accounts_managerUserId_idx" ON "mam_accounts"("managerUserId");

-- CreateIndex
CREATE INDEX "mam_investors_mamAccountId_idx" ON "mam_investors"("mamAccountId");

-- CreateIndex
CREATE INDEX "mam_investors_investorUserId_idx" ON "mam_investors"("investorUserId");

-- CreateIndex
CREATE UNIQUE INDEX "mam_investors_mamAccountId_investorUserId_key" ON "mam_investors"("mamAccountId", "investorUserId");

-- CreateIndex
CREATE UNIQUE INDEX "strategy_providers_userId_key" ON "strategy_providers"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "strategy_providers_accountNumber_key" ON "strategy_providers"("accountNumber");

-- CreateIndex
CREATE UNIQUE INDEX "strategy_providers_strategyName_key" ON "strategy_providers"("strategyName");

-- CreateIndex
CREATE UNIQUE INDEX "strategy_providers_accessToken_key" ON "strategy_providers"("accessToken");

-- CreateIndex
CREATE INDEX "strategy_providers_userId_idx" ON "strategy_providers"("userId");

-- CreateIndex
CREATE INDEX "strategy_providers_isCatalogEligible_isActive_visibility_idx" ON "strategy_providers"("isCatalogEligible", "isActive", "visibility");

-- CreateIndex
CREATE INDEX "copy_followers_strategyId_copyStatus_idx" ON "copy_followers"("strategyId", "copyStatus");

-- CreateIndex
CREATE INDEX "copy_followers_followerUserId_copyStatus_idx" ON "copy_followers"("followerUserId", "copyStatus");

-- CreateIndex
CREATE UNIQUE INDEX "copy_followers_strategyId_followerUserId_key" ON "copy_followers"("strategyId", "followerUserId");

-- CreateIndex
CREATE UNIQUE INDEX "groups_name_key" ON "groups"("name");

-- CreateIndex
CREATE INDEX "groups_accountVariant_idx" ON "groups"("accountVariant");

-- CreateIndex
CREATE INDEX "group_symbols_groupId_idx" ON "group_symbols"("groupId");

-- CreateIndex
CREATE INDEX "group_symbols_symbol_idx" ON "group_symbols"("symbol");

-- CreateIndex
CREATE UNIQUE INDEX "group_symbols_groupId_symbol_key" ON "group_symbols"("groupId", "symbol");

-- CreateIndex
CREATE INDEX "market_sessions_symbol_isActive_idx" ON "market_sessions"("symbol", "isActive");

-- CreateIndex
CREATE UNIQUE INDEX "market_sessions_symbol_dayOfWeek_key" ON "market_sessions"("symbol", "dayOfWeek");

-- CreateIndex
CREATE UNIQUE INDEX "market_holidays_symbol_holidayDate_key" ON "market_holidays"("symbol", "holidayDate");

-- CreateIndex
CREATE INDEX "user_transactions_userId_userType_txnType_idx" ON "user_transactions"("userId", "userType", "txnType");

-- CreateIndex
CREATE INDEX "user_transactions_status_createdAt_idx" ON "user_transactions"("status", "createdAt");

-- CreateIndex
CREATE INDEX "bonus_campaign_tiers_campaignId_minDeposit_idx" ON "bonus_campaign_tiers"("campaignId", "minDeposit");

-- CreateIndex
CREATE INDEX "user_bonus_allocations_userId_status_idx" ON "user_bonus_allocations"("userId", "status");

-- CreateIndex
CREATE INDEX "user_bonus_allocations_status_lotsTraded_idx" ON "user_bonus_allocations"("status", "lotsTraded");

-- AddForeignKey
ALTER TABLE "live_user_kyc" ADD CONSTRAINT "live_user_kyc_userId_fkey" FOREIGN KEY ("userId") REFERENCES "live_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_trading_config" ADD CONSTRAINT "user_trading_config_userId_fkey" FOREIGN KEY ("userId") REFERENCES "live_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_lp_assignment" ADD CONSTRAINT "user_lp_assignment_userId_fkey" FOREIGN KEY ("userId") REFERENCES "live_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mam_accounts" ADD CONSTRAINT "mam_accounts_managerUserId_fkey" FOREIGN KEY ("managerUserId") REFERENCES "live_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mam_investors" ADD CONSTRAINT "mam_investors_mamAccountId_fkey" FOREIGN KEY ("mamAccountId") REFERENCES "mam_accounts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mam_investors" ADD CONSTRAINT "mam_investors_investorUserId_fkey" FOREIGN KEY ("investorUserId") REFERENCES "live_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "strategy_providers" ADD CONSTRAINT "strategy_providers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "live_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "strategy_provider_stats" ADD CONSTRAINT "strategy_provider_stats_strategyId_fkey" FOREIGN KEY ("strategyId") REFERENCES "strategy_providers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "copy_followers" ADD CONSTRAINT "copy_followers_strategyId_fkey" FOREIGN KEY ("strategyId") REFERENCES "strategy_providers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "copy_followers" ADD CONSTRAINT "copy_followers_followerUserId_fkey" FOREIGN KEY ("followerUserId") REFERENCES "live_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "group_symbols" ADD CONSTRAINT "group_symbols_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "groups"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_transactions" ADD CONSTRAINT "user_transactions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "live_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "bonus_campaign_tiers" ADD CONSTRAINT "bonus_campaign_tiers_campaignId_fkey" FOREIGN KEY ("campaignId") REFERENCES "bonus_campaigns"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_bonus_allocations" ADD CONSTRAINT "user_bonus_allocations_userId_fkey" FOREIGN KEY ("userId") REFERENCES "live_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_bonus_allocations" ADD CONSTRAINT "user_bonus_allocations_campaignId_fkey" FOREIGN KEY ("campaignId") REFERENCES "bonus_campaigns"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_bonus_allocations" ADD CONSTRAINT "user_bonus_allocations_tierId_fkey" FOREIGN KEY ("tierId") REFERENCES "bonus_campaign_tiers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_bonus_allocations" ADD CONSTRAINT "user_bonus_allocations_triggeringTxnId_fkey" FOREIGN KEY ("triggeringTxnId") REFERENCES "user_transactions"("id") ON DELETE SET NULL ON UPDATE CASCADE;
