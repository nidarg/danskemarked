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
  constructor(private authService: AuthService) {}

  // ======================
  // Register
  // ======================
  @Post('register')
  async register(@Body() registerDto: RegisterDto): Promise<AuthResponseDto> {
    const { name, email, password } = registerDto;
    return this.authService.register(name, email, password);
  }

  // ======================
  // Login
  // ======================
  @Post('login')
  async login(@Body() loginDto: LoginDto): Promise<AuthResponseDto> {
    const { email, password } = loginDto;
    return this.authService.login(email, password);
  }

  // ======================
  // Refresh Token
  // ======================
  @Post('refresh-token')
  async refreshToken(
    @Body() body: RefreshTokenDto,
  ): Promise<{ access_token: string }> {
    return this.authService.refreshToken(body.refreshToken);
  }

  // ======================
  // Logout
  // ======================
  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(
    @Req() req: { user: { sub: string } }, // tipăm corect `req`
    @Body() body: RefreshTokenDto,
  ): Promise<{ message: string }> {
    return this.authService.logout(req.user.sub, body.refreshToken);
  }

  // ======================
  // Profile
  // ======================
  @Get('profile')
  @UseGuards(JwtAuthGuard)
  async profile(@Req() req: { user: { sub: string } }): Promise<AuthUserDto> {
    return this.authService.getProfile(req.user.sub);
  }

  // ======================
  // Update Profile
  // ======================
  @Patch('update-profile')
  @UseGuards(JwtAuthGuard)
  async updateProfile(
    @Req() req: { user: { sub: string } },
    @Body() body: UpdateProfileDto,
  ): Promise<AuthUserDto> {
    return this.authService.updateProfile(req.user.sub, body);
  }

  // ======================
  // Update Password
  // ======================
  @Patch('update-password')
  @UseGuards(JwtAuthGuard)
  async updatePassword(
    @Req() req: { user: { sub: string } },
    @Body() body: UpdatePasswordDto,
  ): Promise<{ message: string }> {
    return this.authService.updatePassword(
      req.user.sub,
      body.oldPassword,
      body.newPassword,
    );
  }

  // ======================
  // Forgot Password
  // ======================
  @Post('forgot-password')
  async forgotPassword(
    @Body() dto: ForgotPasswordDto,
  ): Promise<{ message: string }> {
    return this.authService.forgotPassword(dto.email);
  }

  // ======================
  // Reset Password
  // ======================
  @Post('reset-password')
  async resetPassword(
    @Body() body: ResetPasswordDto,
  ): Promise<{ message: string }> {
    return this.authService.resetPassword(body.token, body.newPassword);
  }
}
