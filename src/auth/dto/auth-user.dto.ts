export class AuthUserDto {
  id: string;
  name: string;
  email: string;
  role: 'ADMIN' | 'USER';

  accountType: 'INDIVIDUAL' | 'COMPANY';

  companyName?: string;
  vatNumber?: string;
  address?: string;
  phone?: string;
}
