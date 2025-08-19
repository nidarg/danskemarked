// DTO pentru userul returnat în răspuns (fără parolă)
export class AuthUserDto {
  id: string;
  name: string;
  email: string;
  role: 'USER' | 'ADMIN';
}
