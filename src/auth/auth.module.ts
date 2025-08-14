import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaService } from '../prisma/prisma.service';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './jwt-strategy';

@Module({
  imports: [
    PassportModule, // importă Passport pentru a folosi JWT strategy
    JwtModule.register({
      secret: process.env.JWT_SECRET, // cheia secretă pentru semnarea JWT (poți folosi env var)
      signOptions: { expiresIn: process.env.JWT_EXPIRATION }, // token-ul expiră în 1 oră
    }),
  ],
  providers: [AuthService, PrismaService, JwtStrategy], // serviciile disponibile în modul
  controllers: [AuthController], // controller-ul care expune rutele
})
export class AuthModule {}
