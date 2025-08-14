import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService, // serviciul Prisma pentru interacțiunea cu DB
    private jwtService: JwtService, // serviciul JWT pentru generarea token-urilor
  ) {}

  // ======================
  // Înregistrare user
  // ======================
  async register(name: string, email: string, password: string) {
    // 1️⃣ Hash parolei cu bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // 2️⃣ Creează user-ul în baza de date
    const user = await this.prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    // 3️⃣ Pregătește payload-ul pentru JWT
    const payload = { sub: user.id, email: user.email, role: user.role };

    // 4️⃣ Generează token-ul JWT
    const access_token = this.jwtService.sign(payload);

    // 5️⃣ Returnează datele user-ului fără parolă + token
    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      access_token,
    };
  }

  // ======================
  // Login user
  // ======================
  async login(email: string, password: string) {
    // 1️⃣ Găsește user-ul după email
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    // 2️⃣ Compară parola introdusă cu hash-ul stocat
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throw new UnauthorizedException('Invalid credentials');

    // 3️⃣ Pregătește payload-ul pentru JWT
    const payload = { sub: user.id, email: user.email, role: user.role };

    // 4️⃣ Generează token-ul JWT
    const access_token = this.jwtService.sign(payload);

    // 5️⃣ Returnează token-ul + datele user-ului fără parolă
    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      access_token,
    };
  }
}
