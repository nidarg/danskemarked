import {
  Controller,
  Post,
  Body,
  Get,
  Patch,
  UseGuards,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { AuthUserDto } from './dto/auth-user.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { JwtAuthGuard } from './guards/jwt-auth-guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // ======================
  // Register new user
  // ======================
  @Post('register')
  async register(
    @Body() registerDto: RegisterDto,
  ): Promise<AuthResponseDto & { refresh_token: string }> {
    // Apelează serviciul AuthService.register cu DTO-ul complet
    return this.authService.register(registerDto);
  }

  // ======================
  // Login
  // ======================
  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
  ): Promise<AuthResponseDto & { refresh_token: string }> {
    // Apelează serviciul AuthService.login cu DTO-ul complet
    return this.authService.login(loginDto);
  }

  // ======================
  // Refresh access token
  // ======================
  @Post('refresh-token')
  async refreshToken(
    @Body() dto: RefreshTokenDto,
  ): Promise<{ access_token: string }> {
    // Primește refresh token și returnează un nou access token
    return this.authService.refreshToken(dto);
  }

  // ======================
  // Logout
  // ======================
  @Post('logout')
  @UseGuards(JwtAuthGuard) // Protejat cu JWT
  async logout(
    @Req() req: { user: { sub: string } }, // User ID din JWT
    @Body() dto: RefreshTokenDto,
  ): Promise<{ message: string }> {
    // Șterge refresh token-ul din DB
    return this.authService.logout(req.user.sub, dto.refreshToken);
  }

  // ======================
  // Get user profile
  // ======================
  @Get('profile')
  @UseGuards(JwtAuthGuard)
  async profile(
    @Req() req: { user: { userId: string } },
  ): Promise<AuthUserDto> {
    console.log(req.user);
    const user = await this.authService.getProfile(req.user.userId);
    return user;
  }

  // ======================
  // Update profile
  // ======================
  @Patch('update-profile')
  @UseGuards(JwtAuthGuard)
  async updateProfile(
    @Req() req: { user: { userId: string } },
    @Body() body: UpdateProfileDto,
  ): Promise<AuthUserDto> {
    // Actualizează profile-ul userului
    return this.authService.updateProfile(req.user.userId, body);
  }

  // ======================
  // Update password
  // ======================
  @Patch('update-password')
  @UseGuards(JwtAuthGuard)
  async updatePassword(
    @Req() req: { user: { userId: string } },
    @Body() body: UpdatePasswordDto,
  ): Promise<{ message: string }> {
    // Actualizează parola userului logat
    return this.authService.updatePassword(req.user.userId, body);
  }

  // ======================
  // Forgot password
  // ======================
  @Post('forgot-password')
  async forgotPassword(
    @Body() dto: ForgotPasswordDto,
  ): Promise<{ message: string }> {
    // Trimite email pentru resetare parola
    return this.authService.forgotPassword(dto);
  }

  // ======================
  // Reset password
  // ======================
  @Post('reset-password')
  async resetPassword(
    @Body() dto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    // Resetează parola cu token-ul primit
    return this.authService.resetPassword(dto);
  }
}
