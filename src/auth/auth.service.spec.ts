// ==== Mock SendGrid ====
jest.mock('@sendgrid/mail', () => ({
  __esModule: true,
  setApiKey: jest.fn(),
  end: jest.fn().mockResolvedValue({}),
}));

// import * as sgMail from '@sendgrid/mail'; // import după mock
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import {
  UnauthorizedException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';

// ==== Mock pentru Prisma (DB) ====
const mockPrisma = {
  user: {
    create: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  refreshToken: {
    create: jest.fn(),
    findUnique: jest.fn(),
    deleteMany: jest.fn(),
  },
};

// ==== Mock pentru JwtService ====
const mockJwt = {
  sign: jest.fn().mockReturnValue('signed-jwt'),
  verify: jest
    .fn()
    .mockReturnValue({ sub: '1', email: 'john@test.com', role: 'USER' }),
};

// ==== Setăm SendGrid API key pentru test ====
beforeAll(() => {
  process.env.SENDGRID_API_KEY = 'fake-api-key';
});

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: JwtService, useValue: mockJwt },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =======================
  // SERVICIUL EXISTĂ
  // =======================
  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  // =======================
  // REGISTER
  // =======================
  it('should register a new user', async () => {
    const hashed = await bcrypt.hash('password123', 10);
    mockPrisma.user.create.mockResolvedValue({
      id: '1',
      name: 'John',
      email: 'john@test.com',
      role: 'USER',
      password: hashed,
      accountType: 'INDIVIDUAL',
    });
    mockPrisma.refreshToken.create.mockResolvedValue({ token: 'signed-jwt' });

    const result = await service.register({
      name: 'John',
      email: 'john@test.com',
      password: 'password123',
      accountType: 'INDIVIDUAL',
    });

    expect(result.user.email).toBe('john@test.com');
    expect(result).toHaveProperty('access_token');
    expect(result).toHaveProperty('refresh_token');
  });

  // =======================
  // LOGIN
  // =======================
  it('should login with correct credentials', async () => {
    const hashed = await bcrypt.hash('password123', 10);
    mockPrisma.user.findUnique.mockResolvedValue({
      id: '1',
      name: 'John',
      email: 'john@test.com',
      role: 'USER',
      password: hashed,
    });

    const result = await service.login({
      email: 'john@test.com',
      password: 'password123',
    });

    expect(result.user.name).toBe('John');
    expect(result.access_token).toBe('signed-jwt');
  });

  it('should throw UnauthorizedException on invalid login', async () => {
    mockPrisma.user.findUnique.mockResolvedValue(null);

    await expect(
      service.login({ email: 'wrong@test.com', password: 'password' }),
    ).rejects.toThrow(UnauthorizedException);
  });

  // =======================
  // LOGOUT
  // =======================
  it('should logout and delete refresh token', async () => {
    mockPrisma.refreshToken.deleteMany.mockResolvedValue({ count: 1 });

    const result = await service.logout('1', 'signed-jwt');

    expect(result).toEqual({ message: 'Logged out successfully' });
  });

  // =======================
  // REFRESH TOKEN
  // =======================
  it('should refresh access token with valid refresh token', async () => {
    mockPrisma.refreshToken.findUnique.mockResolvedValue({
      token: 'signed-jwt',
    });
    mockPrisma.user.findUnique.mockResolvedValue({
      id: '1',
      name: 'John',
      email: 'john@test.com',
      role: 'USER',
    });

    const result = await service.refreshToken({ refreshToken: 'signed-jwt' });

    expect(result).toEqual({ access_token: 'signed-jwt' });
  });

  it('should throw UnauthorizedException if refresh token not found', async () => {
    mockPrisma.refreshToken.findUnique.mockResolvedValue(null);

    await expect(
      service.refreshToken({ refreshToken: 'invalid-token' }),
    ).rejects.toThrow(UnauthorizedException);
  });

  // =======================
  // GET PROFILE
  // =======================
  it('should return user profile', async () => {
    mockPrisma.user.findUnique.mockResolvedValue({
      id: '1',
      name: 'John',
      email: 'john@test.com',
      role: 'USER',
    });

    const result = await service.getProfile('1');

    expect(result.email).toBe('john@test.com');
  });

  it('should throw NotFoundException if profile not found', async () => {
    mockPrisma.user.findUnique.mockResolvedValue(null);

    await expect(service.getProfile('123')).rejects.toThrow(NotFoundException);
  });

  // =======================
  // UPDATE PROFILE
  // =======================
  it('should update user profile', async () => {
    mockPrisma.user.update.mockResolvedValue({
      id: '1',
      name: 'Johnny',
      email: 'johnny@test.com',
      role: 'USER',
    });

    const result = await service.updateProfile('1', {
      name: 'Johnny',
      email: 'johnny@test.com',
    });

    expect(result.name).toBe('Johnny');
  });

  // =======================
  // UPDATE PASSWORD
  // =======================
  it('should update password if old password matches', async () => {
    const hashed = await bcrypt.hash('oldPass', 10);
    mockPrisma.user.findUnique.mockResolvedValue({ id: '1', password: hashed });
    mockPrisma.user.update.mockResolvedValue({ id: '1' });

    const result = await service.updatePassword('1', {
      oldPassword: 'oldPass',
      newPassword: 'newPass',
    });

    expect(result).toEqual({ message: 'Password updated successfully' });
  });

  it('should throw BadRequestException if old password is wrong', async () => {
    // hash pentru parola curentă
    const hashed = await bcrypt.hash('oldPass', 10);

    // mock pentru findUnique returnând utilizator cu parola hashed
    mockPrisma.user.findUnique.mockResolvedValue({ id: '1', password: hashed });

    // verificăm că updatePassword aruncă UnauthorizedException
    await expect(
      service.updatePassword('1', {
        oldPassword: 'wrongPass',
        newPassword: 'newPass',
      }),
    ).rejects.toThrow(UnauthorizedException); // <- aici nu mai există linie ruptă greșită
  });

  // =======================
  // FORGOT PASSWORD (SendGrid)
  // =======================
  it('should send forgot password email', async () => {
    mockPrisma.user.findUnique.mockResolvedValue({
      id: '1',
      email: 'john@test.com',
    });

    // Înainte de test
    const sendEmailSpy = jest
      .spyOn(service as any, 'sendEmail')
      .mockResolvedValue(undefined);

    const result = await service.forgotPassword({ email: 'john@test.com' });

    expect(result).toEqual({
      message: 'If that email is registered, a reset link was sent.',
    });
    expect(sendEmailSpy).toHaveBeenCalledWith(
      'john@test.com',
      expect.any(String),
      expect.any(String),
    );
  });

  it('should throw NotFoundException if email not found', async () => {
    mockPrisma.user.findUnique.mockResolvedValue(null);

    await expect(
      service.forgotPassword({ email: 'notfound@test.com' }),
    ).rejects.toThrow(NotFoundException);
  });

  // =======================
  // RESET PASSWORD
  // =======================
  it('should reset password with valid token', async () => {
    mockJwt.verify.mockReturnValue({ sub: '1' });
    mockPrisma.user.update.mockResolvedValue({ id: '1' });

    const result = await service.resetPassword({
      token: 'valid-token',
      newPassword: 'newPass',
    });

    expect(result).toEqual({ message: 'Password reset successfully' });
  });

  it('should throw BadRequestException if token invalid', async () => {
    mockJwt.verify.mockImplementation(() => {
      throw new Error('Invalid');
    });

    await expect(
      service.resetPassword({ token: 'bad-token', newPassword: 'newPass' }),
    ).rejects.toThrow(BadRequestException); // <- aici închizi expect-ul
  });
});
