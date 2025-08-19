import { AuthUserDto } from './auth-user.dto';

// DTO pentru răspunsul serviciului de autentificare
export class AuthResponseDto {
  user: AuthUserDto;
  access_token: string;
}
