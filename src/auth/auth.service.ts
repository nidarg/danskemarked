// Importăm decoratori și clase utile din NestJS
import {
  Injectable, // Marchează clasa ca un serviciu ce poate fi injectat
  UnauthorizedException, // Aruncată pentru erori de autentificare
  NotFoundException, // Aruncată dacă un resource (ex: user) nu există
  BadRequestException, // Aruncată pentru request invalid
  Logger, // Util pentru log-uri
} from '@nestjs/common';

// Importăm PrismaService pentru acces la baza de date
import { PrismaService } from '../prisma/prisma.service';

// Importăm bcrypt pentru hashing și verificare parole
import * as bcrypt from 'bcrypt';

// Importăm JwtService pentru generare și verificare token-uri JWT
import { JwtService } from '@nestjs/jwt';

// Importăm librăria SendGrid pentru trimitere email-uri
import * as sgMail from '@sendgrid/mail';

// DTO-uri (Data Transfer Objects) folosite pentru request/response
import { AuthResponseDto } from './dto/auth-response.dto';
import { AuthUserDto } from './dto/auth-user.dto';
import { Role } from '@prisma/client';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';

// Declarăm clasa ca fiind un serviciu injectabil
@Injectable()
export class AuthService {
  // Logger pentru mesaje din serviciu
  private readonly logger = new Logger(AuthService.name);

  // Injectăm PrismaService și JwtService prin constructor
  constructor(
    private readonly prisma: PrismaService, // pentru acces DB
    private readonly jwtService: JwtService, // pentru token-uri JWT
  ) {
    // Citim API key-ul pentru SendGrid din variabilele de mediu
    const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;

    // Dacă nu există, aruncăm eroare
    if (!SENDGRID_API_KEY) throw new Error('SENDGRID_API_KEY is not defined');

    // Configurăm SendGrid cu cheia citită
    sgMail.setApiKey(SENDGRID_API_KEY);
  }

  // ============================================================
  // Helper: Transformă un obiect User (din Prisma) într-un DTO
  // ============================================================
  private toAuthUserDto(user: {
    id: string;
    name: string;
    email: string;
    role: Role;
    accountType: 'INDIVIDUAL' | 'COMPANY';
    companyName?: string | null;
    vatNumber?: string | null;
    address?: string | null;
    phone?: string | null;
  }): AuthUserDto {
    return {
      id: user.id, // ID user
      name: user.name, // Nume
      email: user.email, // Email
      role: user.role === 'ADMIN' ? 'ADMIN' : 'USER', // Rol mapat
      accountType: user.accountType, // Tip cont
      companyName: user.companyName ?? undefined, // Company name dacă există
      vatNumber: user.vatNumber ?? undefined, // VAT number dacă există
      address: user.address ?? undefined, // Adresă
      phone: user.phone ?? undefined, // Telefon
    };
  }

  // ============================================================
  // Helper: Trimitere email prin SendGrid
  // ============================================================
  private async sendEmail(
    to: string, // Destinatar
    subject: string, // Subiect email
    html: string, // Conținut HTML
  ): Promise<void> {
    const mailData = {
      to, // Email destinatar
      from: process.env.EMAIL_FROM ?? '', // Expeditor (din env)
      subject, // Subiect
      html, // Conținut HTML
    };
    try {
      await sgMail.send(mailData); // Trimite email
    } catch (error: unknown) {
      // Logăm eroarea pentru debugging
      this.logger.error(
        'SendGrid email error',
        error instanceof Error ? error.stack : String(error),
      );
      // Aruncăm excepție dacă emailul nu s-a trimis
      throw new BadRequestException('Failed to send email');
    }
  }

  // ============================================================
  // Register - Înregistrare user nou
  // ============================================================
  async register(
    dto: RegisterDto, // DTO cu datele de înregistrare
  ): Promise<AuthResponseDto & { refresh_token: string }> {
    // Verificăm dacă email-ul există deja în DB
    const existingUser = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (existingUser) throw new BadRequestException('Email already registered');

    // Facem hash la parolă
    const hashedPassword = await bcrypt.hash(dto.password, 10);

    // Creăm user în baza de date
    const user = await this.prisma.user.create({
      data: {
        name: dto.name,
        email: dto.email,
        password: hashedPassword,
        accountType: dto.accountType,
        companyName: dto.companyName ?? null,
        vatNumber: dto.vatNumber ?? null,
        address: dto.address ?? null,
        phone: dto.phone ?? null,
      },
    });

    // Pregătim payload pentru JWT
    const payload = { sub: user.id, email: user.email, role: user.role };

    // Generăm access și refresh token-uri
    const access_token = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refresh_token = this.jwtService.sign(payload, { expiresIn: '7d' });

    // Salvăm refresh token în DB
    await this.prisma.refreshToken.create({
      data: {
        token: refresh_token,
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // expiră în 7 zile
      },
    });

    // Returnăm user + token-uri
    return { user: this.toAuthUserDto(user), access_token, refresh_token };
  }

  // ============================================================
  // Login - Autentificare user existent
  // ============================================================
  async login(
    dto: LoginDto, // DTO cu email și parolă
  ): Promise<AuthResponseDto & { refresh_token: string }> {
    // Căutăm user după email
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    // Verificăm parola
    const isMatch = await bcrypt.compare(dto.password, user.password);
    if (!isMatch) throw new UnauthorizedException('Invalid credentials');

    // Generăm token-uri
    const payload = { sub: user.id, email: user.email, role: user.role };
    const access_token = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refresh_token = this.jwtService.sign(payload, { expiresIn: '7d' });

    // Salvăm refresh token în DB
    await this.prisma.refreshToken.create({
      data: {
        token: refresh_token,
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    return { user: this.toAuthUserDto(user), access_token, refresh_token };
  }

  // ============================================================
  // Logout - Șterge refresh token din DB
  // ============================================================
  async logout(
    userId: string, // ID user
    refreshToken: string, // Refresh token
  ): Promise<{ message: string }> {
    // Ștergem token-ul din DB
    await this.prisma.refreshToken.deleteMany({
      where: { userId, token: refreshToken },
    });
    return { message: 'Logged out successfully' };
  }

  // ============================================================
  // Refresh token - Generează un nou access token
  // ============================================================
  async refreshToken(dto: RefreshTokenDto): Promise<{ access_token: string }> {
    try {
      // Verificăm refresh token-ul primit
      const payload = this.jwtService.verify<{
        sub: string;
        email: string;
        role: Role;
      }>(dto.refreshToken);

      // Căutăm token-ul în DB
      const tokenInDb = await this.prisma.refreshToken.findUnique({
        where: { token: dto.refreshToken },
      });
      if (!tokenInDb) throw new UnauthorizedException('Invalid refresh token');

      // Căutăm user-ul
      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
      });
      if (!user) throw new UnauthorizedException('User not found');

      // Generăm un nou access token
      const access_token = this.jwtService.sign(
        { sub: user.id, email: user.email, role: user.role },
        { expiresIn: '15m' },
      );

      return { access_token };
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  // ============================================================
  // Forgot password - Trimite email cu link resetare parolă
  // ============================================================
  async forgotPassword(dto: ForgotPasswordDto): Promise<{ message: string }> {
    // Căutăm user după email
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (!user) throw new NotFoundException('User not found');

    // Creăm token resetare valabil 1h
    const token = this.jwtService.sign({ sub: user.id }, { expiresIn: '1h' });

    // Construim link pentru frontend
    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

    // Trimitem email
    await this.sendEmail(
      user.email,
      'Reset your password',
      `<a href="${resetLink}">Reset Password</a>`,
    );

    return { message: 'If that email is registered, a reset link was sent.' };
  }

  // ============================================================
  // Reset password - Setează parolă nouă pe baza token-ului
  // ============================================================
  async resetPassword(dto: ResetPasswordDto): Promise<{ message: string }> {
    try {
      // Verificăm token-ul
      const payload = this.jwtService.verify<{ sub: string }>(dto.token);

      // Facem hash la noua parolă
      const hashedPassword = await bcrypt.hash(dto.newPassword, 10);

      // Updatăm user-ul
      await this.prisma.user.update({
        where: { id: payload.sub },
        data: { password: hashedPassword },
      });

      return { message: 'Password reset successfully' };
    } catch {
      throw new BadRequestException('Invalid or expired token');
    }
  }

  // ============================================================
  // Update password - User logat își schimbă parola
  // ============================================================
  async updatePassword(
    userId: string, // ID-ul user-ului
    dto: UpdatePasswordDto, // DTO cu parole
  ): Promise<{ message: string }> {
    // Căutăm user-ul
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    // Verificăm parola veche
    const isMatch = await bcrypt.compare(dto.oldPassword, user.password);
    if (!isMatch) throw new UnauthorizedException('Old password is incorrect');

    // Facem hash la noua parolă
    const hashedPassword = await bcrypt.hash(dto.newPassword, 10);

    // Updatăm parola
    await this.prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword },
    });

    return { message: 'Password updated successfully' };
  }

  // ============================================================
  // Get profile - Returnează profilul user-ului logat
  // ============================================================
  async getProfile(userId: string): Promise<AuthUserDto> {
    // Căutăm user-ul în DB
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    // Dacă nu există, aruncăm excepție
    if (!user) throw new NotFoundException('User not found');

    // Returnăm user-ul ca DTO
    return this.toAuthUserDto(user);
  }

  // ============================================================
  // Update profile - Updatează datele user-ului
  // ============================================================
  async updateProfile(
    userId: string, // ID-ul user-ului
    dto: UpdateProfileDto, // DTO cu datele noi
  ): Promise<AuthUserDto> {
    // Updatăm user-ul în DB
    const user = await this.prisma.user.update({
      where: { id: userId },
      data: {
        name: dto.name,
        email: dto.email,
        companyName: dto.companyName,
        vatNumber: dto.vatNumber,
        address: dto.address,
        phone: dto.phone,
      },
    });

    // Returnăm user-ul updatat ca DTO
    return this.toAuthUserDto(user);
  }
}
