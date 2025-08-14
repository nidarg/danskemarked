import { SetMetadata } from '@nestjs/common';

// Tipurile posibile de roluri
export type Role = 'USER' | 'ADMIN';

// Decorator pentru a atașa roluri la o rută
export const Roles = (...roles: Role[]) => SetMetadata('roles', roles);
