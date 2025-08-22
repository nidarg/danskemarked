-- CreateEnum
CREATE TYPE "public"."AccountType" AS ENUM ('INDIVIDUAL', 'COMPANY');

-- AlterTable
ALTER TABLE "public"."User" ADD COLUMN     "accountType" "public"."AccountType" NOT NULL DEFAULT 'INDIVIDUAL',
ADD COLUMN     "address" TEXT,
ADD COLUMN     "companyName" TEXT,
ADD COLUMN     "phone" TEXT,
ADD COLUMN     "vatNumber" TEXT;
