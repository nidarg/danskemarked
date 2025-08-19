/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
import {
  Injectable, // Decorator to mark this class as injectable in NestJS
  UnauthorizedException, // Exception for 401 responses
  NotFoundException, // Exception for 404 responses
  BadRequestException, // Exception for 400 responses
  Logger, // Logger class provided by NestJS
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service'; // Prisma DB service
import * as bcrypt from 'bcrypt'; // Library to hash and compare passwords
import { JwtService } from '@nestjs/jwt'; // JWT handling service
import sgMail from '@sendgrid/mail'; // SendGrid mail service

// ======================
// Interfaces
// ======================
export interface AuthTokens {
  access_token: string; // JWT access token
  refresh_token: string; // JWT refresh token
}

export interface AuthUser {
  id: string; // User ID
  name: string; // User name
  email: string; // User email
  role: 'USER' | 'ADMIN'; // User role
}

@Injectable() // Marks this class as NestJS service
export class AuthService {
  private readonly logger = new Logger(AuthService.name); // Logger instance

  constructor(
    private readonly prisma: PrismaService, // Inject Prisma DB service
    private readonly jwtService: JwtService, // Inject JWT service
  ) {
    // Set SendGrid API key safely
    const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
    if (!SENDGRID_API_KEY) {
      throw new Error('SENDGRID_API_KEY is not defined'); // Throw if missing
    }
    sgMail.setApiKey(SENDGRID_API_KEY); // Initialize SendGrid
  }

  // ======================
  // Send email using SendGrid
  // ======================
  private async sendEmail(
    to: string,
    subject: string,
    html: string,
  ): Promise<void> {
    const mailData = {
      to,
      from: process.env.EMAIL_FROM ?? '', // Fallback to empty string if not defined
      subject,
      html,
    };

    try {
      await sgMail.send(mailData); // Send email
    } catch (error: unknown) {
      this.logger.error(
        'SendGrid email error',
        error instanceof Error ? error.stack : String(error), // Log error stack
      );
      throw new BadRequestException('Failed to send email'); // Throw user-friendly error
    }
  }

  // ======================
  // Register a new user
  // ======================
  async register(
    name: string,
    email: string,
    password: string,
  ): Promise<{ user: AuthUser } & AuthTokens> {
    const hashedPassword = await bcrypt.hash(password, 10); // Hash password

    const user = await this.prisma.user.create({
      data: { name, email, password: hashedPassword }, // Create user in DB
    });

    const payload = { sub: user.id, email: user.email, role: user.role }; // JWT payload
    const access_token = this.jwtService.sign(payload, { expiresIn: '15m' }); // Access token 15 min
    const refresh_token = this.jwtService.sign(payload, { expiresIn: '7d' }); // Refresh token 7 days

    await this.prisma.refreshToken.create({
      data: {
        token: refresh_token,
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days expiry
      },
    });

    return { user, access_token, refresh_token }; // Return user and tokens
  }

  // ======================
  // Login user
  // ======================
  async login(
    email: string,
    password: string,
  ): Promise<{ user: AuthUser } & AuthTokens> {
    const user = await this.prisma.user.findUnique({ where: { email } }); // Find user by email
    if (!user) throw new UnauthorizedException('Invalid credentials'); // Throw if not found

    const isMatch = await bcrypt.compare(password, user.password); // Compare passwords
    if (!isMatch) throw new UnauthorizedException('Invalid credentials'); // Throw if mismatch

    const payload = { sub: user.id, email: user.email, role: user.role }; // JWT payload
    const access_token = this.jwtService.sign(payload, { expiresIn: '15m' }); // Access token
    const refresh_token = this.jwtService.sign(payload, { expiresIn: '7d' }); // Refresh token

    await this.prisma.refreshToken.create({
      data: {
        token: refresh_token,
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days expiry
      },
    });

    return { user, access_token, refresh_token }; // Return user and tokens
  }

  // ======================
  // Logout user
  // ======================
  async logout(
    userId: string,
    refreshToken: string,
  ): Promise<{ message: string }> {
    await this.prisma.refreshToken.deleteMany({
      where: { userId, token: refreshToken }, // Delete specific refresh token
    });
    return { message: 'Logged out successfully' }; // Return success message
  }

  // ======================
  // Refresh access token
  // ======================
  async refreshToken(refreshToken: string): Promise<{ access_token: string }> {
    try {
      const payload = this.jwtService.verify<{
        sub: string;
        email: string;
        role: string;
      }>(
        refreshToken, // Verify refresh token
      );

      const tokenInDb = await this.prisma.refreshToken.findUnique({
        where: { token: refreshToken }, // Check DB
      });
      if (!tokenInDb) throw new UnauthorizedException('Invalid refresh token'); // Token not found

      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
      }); // Find user
      if (!user) throw new UnauthorizedException('User not found'); // User not found

      const newAccessToken = this.jwtService.sign(
        { sub: user.id, email: user.email, role: user.role }, // New JWT payload
        { expiresIn: '15m' }, // 15 min expiry
      );

      return { access_token: newAccessToken }; // Return new access token
    } catch {
      throw new UnauthorizedException('Invalid refresh token'); // Invalid token
    }
  }

  // ======================
  // Get user profile
  // ======================
  async getProfile(userId: string): Promise<AuthUser> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } }); // Find user
    if (!user) throw new NotFoundException('User not found'); // Throw if not found

    return { id: user.id, name: user.name, email: user.email, role: user.role }; // Return profile
  }

  // ======================
  // Update user profile
  // ======================
  async updateProfile(
    userId: string,
    data: { name?: string; email?: string },
  ): Promise<AuthUser> {
    const updateData: Record<string, string> = {}; // Prepare update object
    if (data.name) updateData.name = data.name; // Update name if provided
    if (data.email) updateData.email = data.email; // Update email if provided

    const user = await this.prisma.user.update({
      where: { id: userId }, // Select user
      data: updateData, // Update fields
    });

    return { id: user.id, name: user.name, email: user.email, role: user.role }; // Return updated user
  }

  // ======================
  // Update password
  // ======================
  async updatePassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } }); // Find user
    if (!user) throw new NotFoundException('User not found'); // Throw if missing

    const isMatch = await bcrypt.compare(oldPassword, user.password); // Compare old password
    if (!isMatch) throw new BadRequestException('Old password incorrect'); // Throw if mismatch

    const hashed = await bcrypt.hash(newPassword, 10); // Hash new password
    await this.prisma.user.update({
      where: { id: userId },
      data: { password: hashed }, // Update password in DB
    });

    return { message: 'Password updated successfully' }; // Return success
  }

  // ======================
  // Forgot password (send reset email)
  // ======================
  async forgotPassword(email: string): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({ where: { email } }); // Find user
    if (!user) throw new NotFoundException('User not found'); // Throw if missing

    const token = this.jwtService.sign({ sub: user.id }, { expiresIn: '15m' }); // Generate reset token
    const resetLink = `${process.env.FRONTEND_URL ?? 'http://localhost:3000'}/reset-password?token=${token}`; // Reset link

    await this.sendEmail(
      user.email,
      'Reset your password',
      `<p>Click the link to reset your password: <a href="${resetLink}">Reset Password</a></p>`,
    );

    return { message: 'Password reset email sent' }; // Return success message
  }

  // ======================
  // Reset password
  // ======================
  async resetPassword(
    token: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    try {
      const payload = this.jwtService.verify<{ sub: string }>(token); // Verify token
      const hashed = await bcrypt.hash(newPassword, 10); // Hash new password

      await this.prisma.user.update({
        where: { id: payload.sub },
        data: { password: hashed }, // Update password
      });

      return { message: 'Password reset successfully' }; // Return success
    } catch {
      throw new BadRequestException('Invalid or expired token'); // Invalid token
    }
  }
}
