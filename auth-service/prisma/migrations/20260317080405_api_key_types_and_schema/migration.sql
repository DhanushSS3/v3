/*
  Warnings:

  - Added the required column `updatedAt` to the `api_keys` table without a default value. This is not possible if the table is not empty.
  - Made the column `label` on table `api_keys` required. This step will fail if there are existing NULL values in that column.

*/
-- CreateEnum
CREATE TYPE "ApiKeyType" AS ENUM ('hmac', 'rsa', 'ed25519');

-- AlterTable
ALTER TABLE "api_keys" ADD COLUMN     "keyType" "ApiKeyType" NOT NULL DEFAULT 'hmac',
ADD COLUMN     "publicKey" TEXT,
ADD COLUMN     "updatedAt" TIMESTAMPTZ NOT NULL,
ALTER COLUMN "keyHash" DROP NOT NULL,
ALTER COLUMN "label" SET NOT NULL;
