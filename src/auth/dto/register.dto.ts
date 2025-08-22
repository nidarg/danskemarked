import { IsEmail, IsEnum, IsOptional, IsString } from 'class-validator';

export class RegisterDto {
  @IsString()
  name: string;

  @IsEmail()
  email: string;

  @IsString()
  password: string;

  @IsEnum(['INDIVIDUAL', 'COMPANY'])
  accountType: 'INDIVIDUAL' | 'COMPANY';

  // Only required if accountType = COMPANY
  @IsOptional()
  @IsString()
  companyName?: string;

  @IsOptional()
  @IsString()
  vatNumber?: string;

  @IsOptional()
  @IsString()
  address?: string;

  @IsOptional()
  @IsString()
  phone?: string;
}
