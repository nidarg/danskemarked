import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
// Injectable: face clasa injectabilă în NestJS
// CanActivate: interfață pe care trebuie să o implementeze orice guard
// ExecutionContext: oferă contextul cererii HTTP (request, response, handler etc.)

import { Reflector } from '@nestjs/core';
// Reflector: helper NestJS pentru citirea metadatelor definite pe rute sau controllere
import { Request } from 'express'; // importăm tipul Request pentru tipizare corectă

interface AuthenticatedUser {
  userId: string;
  email: string;
  role: 'USER' | 'ADMIN';
}

@Injectable()
// Marchează clasa ca fiind injectabilă în container-ul NestJS
export class RolesGuard implements CanActivate {
  // Implementăm interfața CanActivate pentru a crea un guard personalizat

  constructor(private reflector: Reflector) {}
  // Injectăm Reflector pentru a putea citi metadatele 'roles' definite pe rute

  canActivate(context: ExecutionContext): boolean {
    // Metoda principală a guard-ului, returnează true dacă user-ul are acces, false altfel

    // obține lista de roluri necesare de pe handler-ul curent
    const requiredRoles = this.reflector.get<('USER' | 'ADMIN')[]>(
      'roles',
      context.getHandler(),
    );
    if (!requiredRoles) return true;
    // Preia metadatele 'roles' atașate metodei (handler-ului) curente
    // Dacă ruta nu are roluri specificate, requiredRoles va fi undefined

    const request = context
      .switchToHttp()
      .getRequest<Request & { user?: AuthenticatedUser }>();
    // Obține obiectul request din contextul HTTP (Express/NestJS)

    const user = request.user;
    // User-ul autentificat este setat anterior de JwtAuthGuard în request.user
    // user poate fi undefined, deci verificăm

    if (!user) {
      return false; // dacă nu există user, nu poate accesa ruta
    }
    return requiredRoles.includes(user.role);
    // Verifică dacă rolul user-ului se află în lista de roluri permise
    // Dacă da, returnează true (permite accesul)
    // Dacă nu, returnează false → NestJS va răspunde cu 403 Forbidden
  }
}
