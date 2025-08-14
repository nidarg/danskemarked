import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

// Tip pentru user returnat fără parolă
interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: 'USER' | 'ADMIN';
}

// Tip pentru răspunsul AuthService
interface AuthResponse {
  user: AuthUser;
  access_token: string;
}

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  // Ruta POST /auth/register
  @Post('register')
  async register(@Body() registerDto: RegisterDto): Promise<AuthResponse> {
    const { name, email, password } = registerDto;
    return this.authService.register(name, email, password);
  }

  // Ruta POST /auth/login
  @Post('login')
  async login(@Body() loginDto: LoginDto): Promise<AuthResponse> {
    const { email, password } = loginDto;
    return this.authService.login(email, password);
  }
}
