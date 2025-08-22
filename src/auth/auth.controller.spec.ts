// Importăm utilitățile de test din NestJS
import { Test, TestingModule } from '@nestjs/testing';
// Importăm controllerul pe care îl testăm
import { AuthController } from './auth.controller';
// Importăm serviciul (pe care îl vom spiona în teste)
import { AuthService } from './auth.service';
// Importăm DTO-urile folosite în metode
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

describe('AuthController', () => {
  let controller: AuthController; // instanța controllerului testat
  let service: AuthService; // instanța serviciului (mock-uit)

  beforeEach(async () => {
    // Construim un modul de testare cu controllerul și un serviciu mock-uit
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          // Înlocuim AuthService cu un obiect mock cu metode goale
          provide: AuthService,
          useValue: {
            register: jest.fn(),
            login: jest.fn(),
            refreshToken: jest.fn(),
            logout: jest.fn(),
            getProfile: jest.fn(),
            updateProfile: jest.fn(),
            updatePassword: jest.fn(),
            forgotPassword: jest.fn(),
            resetPassword: jest.fn(),
          },
        },
      ],
    }).compile();

    // Obținem instanțele controller și service din modul
    controller = module.get<AuthController>(AuthController);
    service = module.get<AuthService>(AuthService);
  });

  // ======================
  // TEST: Controller definit
  // ======================
  it('should be defined', () => {
    expect(controller).toBeDefined(); // verificăm că controllerul există
  });

  // ======================
  // REGISTER
  // ======================
  it('should register a new user', async () => {
    // definim DTO-ul de intrare
    const dto: RegisterDto = {
      name: 'John',
      email: 'john@test.com',
      password: 'pass123',
      accountType: 'INDIVIDUAL',
    };

    // Spionăm metoda `register` din service și îi dăm un răspuns fake
    jest.spyOn(service, 'register').mockResolvedValueOnce({
      user: {
        id: '1',
        name: 'John',
        email: 'john@test.com',
        role: 'USER',
        accountType: 'INDIVIDUAL',
      },
      access_token: 'access',
      refresh_token: 'refresh',
    });

    // Apelăm metoda controllerului
    const result = await controller.register(dto);

    // Verificăm că răspunsul conține emailul corect
    expect(result.user.email).toBe('john@test.com');
    // Verificăm că service-ul a fost apelat cu parametrii corecți
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(service.register).toHaveBeenCalledWith({
      accountType: 'INDIVIDUAL',
      email: 'john@test.com',
      name: 'John',
      password: 'pass123',
    });
  });

  // ======================
  // LOGIN
  // ======================
  it('should login a user', async () => {
    const dto: LoginDto = { email: 'john@test.com', password: 'pass123' };

    jest.spyOn(service, 'login').mockResolvedValueOnce({
      user: {
        id: '1',
        name: 'John',
        email: 'john@test.com',
        role: 'USER',
        accountType: 'INDIVIDUAL',
      },
      access_token: 'access',
      refresh_token: 'refresh',
    });

    const result = await controller.login(dto);

    expect(result.access_token).toBe('access');
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(service.login).toHaveBeenCalledWith({
      email: 'john@test.com',
      password: 'pass123',
    });
  });

  // ======================
  // REFRESH TOKEN
  // ======================
  it('should refresh token', async () => {
    const dto: RefreshTokenDto = { refreshToken: 'refresh123' };

    jest
      .spyOn(service, 'refreshToken')
      .mockResolvedValueOnce({ access_token: 'newAccess' });

    const result = await controller.refreshToken(dto);

    expect(result.access_token).toBe('newAccess');
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(service.refreshToken).toHaveBeenCalledWith({
      refreshToken: 'refresh123',
    });
  });

  // ======================
  // LOGOUT
  // ======================
  it('should logout user', async () => {
    const req = { user: { sub: '1' } };
    const dto: RefreshTokenDto = { refreshToken: 'refresh123' };

    jest
      .spyOn(service, 'logout')
      .mockResolvedValueOnce({ message: 'Logged out successfully' });

    const result = await controller.logout(req, dto);

    expect(result.message).toBe('Logged out successfully');
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(service.logout).toHaveBeenCalledWith('1', 'refresh123');
  });

  // ======================
  // PROFILE
  // ======================
  it('should return profile', async () => {
    const req = { user: { userId: '1' } };

    jest.spyOn(service, 'getProfile').mockResolvedValueOnce({
      id: '1',
      name: 'John',
      email: 'john@test.com',
      role: 'USER',
      accountType: 'INDIVIDUAL',
    });

    const result = await controller.profile(req);

    expect(result.email).toBe('john@test.com');
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(service.getProfile).toHaveBeenCalledWith('1');
  });

  // ======================
  // UPDATE PROFILE
  // ======================
  it('should update profile', async () => {
    const req = { user: { userId: '1' } };
    const dto: UpdateProfileDto = { name: 'Johnny', email: 'johnny@test.com' };

    jest.spyOn(service, 'updateProfile').mockResolvedValueOnce({
      id: '1',
      name: 'Johnny',
      email: 'johnny@test.com',
      role: 'USER',
      accountType: 'INDIVIDUAL',
    });

    const result = await controller.updateProfile(req, dto);

    expect(result.name).toBe('Johnny');
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(service.updateProfile).toHaveBeenCalledWith('1', dto);
  });

  // ======================
  // UPDATE PASSWORD
  // ======================
  it('should update password', async () => {
    const req = { user: { userId: '1' } };
    const dto: UpdatePasswordDto = {
      oldPassword: 'oldPass',
      newPassword: 'newPass',
    };

    jest.spyOn(service, 'updatePassword').mockResolvedValueOnce({
      message: 'Password updated successfully',
    });

    const result = await controller.updatePassword(req, dto);

    expect(result.message).toBe('Password updated successfully');
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(service.updatePassword).toHaveBeenCalledWith('1', {
      newPassword: 'newPass',
      oldPassword: 'oldPass',
    });
  });

  // ======================
  // FORGOT PASSWORD
  // ======================
  it('should send forgot password email', async () => {
    const dto: ForgotPasswordDto = { email: 'john@test.com' };

    jest.spyOn(service, 'forgotPassword').mockResolvedValueOnce({
      message: 'Password reset email sent',
    });

    const result = await controller.forgotPassword(dto);

    expect(result.message).toBe('Password reset email sent');
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(service.forgotPassword).toHaveBeenCalledWith({
      email: 'john@test.com',
    });
  });

  // ======================
  // RESET PASSWORD
  // ======================
  it('should reset password', async () => {
    const dto: ResetPasswordDto = {
      token: 'resetToken',
      newPassword: 'newPass',
    };

    jest.spyOn(service, 'resetPassword').mockResolvedValueOnce({
      message: 'Password reset successfully',
    });

    const result = await controller.resetPassword(dto);

    expect(result.message).toBe('Password reset successfully');
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(service.resetPassword).toHaveBeenCalledWith({
      newPassword: 'newPass',
      token: 'resetToken',
    });
  });
});
