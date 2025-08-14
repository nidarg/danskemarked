import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy, JwtFromRequestFunction } from 'passport-jwt';

// Tip pentru payload-ul JWT
interface JwtPayload {
  sub: string;
  email: string;
  role: 'USER' | 'ADMIN';
}

// Tip pentru user-ul atașat la request
interface AuthenticatedUser {
  userId: string;
  email: string;
  role: 'USER' | 'ADMIN';
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      jwtFromRequest:
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
        ExtractJwt.fromAuthHeaderAsBearerToken() as unknown as JwtFromRequestFunction,
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET!,
    });
  }

  // Fără async pentru că nu avem operații await
  validate(payload: JwtPayload): AuthenticatedUser {
    return {
      userId: payload.sub,
      email: payload.email,
      role: payload.role,
    };
  }
}
