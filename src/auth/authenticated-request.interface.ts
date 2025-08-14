import { Request } from 'express';

// Tip pentru user-ul autentificat atașat la request
export interface AuthenticatedRequest extends Request {
  user: {
    userId: string;
    email: string;
    role: 'USER' | 'ADMIN';
  };
}
