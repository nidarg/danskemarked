# 🔐 Authentication Module – NestJS + Prisma + JWT + SendGrid

This project is an **authentication system** built with **NestJS** and **Prisma**, featuring JWT authentication, refresh tokens, and password reset via email.

---

## 🚀 Features

- ✅ User registration
- ✅ User login
- ✅ Access + Refresh tokens
- ✅ Logout
- ✅ Get profile
- ✅ Update profile
- ✅ Change password
- ✅ Forgot/Reset password (via email)

---

## 📬 Postman Collection

You can test all authentication endpoints directly via our Postman workspace:

🔗 [Open Authentication Collection in Postman](https://winter-moon-399424.postman.co/workspace/danskemarked~b3290832-af7e-45a8-b1c8-07ba6da62651/collection/3718363-bc6ae3cb-f0f2-45cb-8744-bd3aff132bf6?action=share&source=copy-link&creator=3718363)

## 📦 Installation

Clone the repository and install dependencies:

```bash
npm install

Environment variables

Create a .env file and configure:
Environment variables

DATABASE_URL="postgresql://user:password@localhost:5432/dbname"
JWT_SECRET="supersecret"
SENDGRID_API_KEY="your-sendgrid-api-key"
EMAIL_FROM="noreply@yourapp.com"
FRONTEND_URL="http://localhost:3000"
🛠 API Endpoints
1. Register

POST /auth/register

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "mypassword"
}

2. Login

POST /auth/login

{
  "email": "john@example.com",
  "password": "mypassword"
}


Returns:

{
  "access_token": "jwt-token",
  "refresh_token": "jwt-refresh-token"
}

3. Refresh Token

POST /auth/refresh-token

{
  "refreshToken": "jwt-refresh-token"
}

4. Logout

POST /auth/logout
Requires Authorization header with access token.

{
  "refreshToken": "jwt-refresh-token"
}

5. Get Profile

GET /auth/profile
Requires Authorization header:

Authorization: Bearer ACCESS_TOKEN

6. Update Profile

PATCH /auth/update-profile
Requires Authorization header.

{
  "name": "John Smith",
  "email": "john.smith@example.com"
}

7. Update Password

PATCH /auth/update-password
Requires Authorization header.

{
  "oldPassword": "mypassword",
  "newPassword": "newpassword123"
}

8. Forgot Password

POST /auth/forgot-password

{
  "email": "john@example.com"
}


Sends a reset link by email:

http://localhost:3000/reset-password?token=RESET_TOKEN

9. Reset Password

POST /auth/reset-password

{
  "token": "reset-token-from-email",
  "newPassword": "newpassword123"
}

🔒 Security Notes

Access tokens expire in 15 minutes

Refresh tokens expire in 7 days

Passwords are stored using bcrypt hashing

Password reset tokens expire in 15 minutes

⚡ Quick Start with cURL
Register a user
curl -X POST http://localhost:4000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"John Doe","email":"john@example.com","password":"mypassword"}'

Login
curl -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com","password":"mypassword"}'

Get Profile (replace ACCESS_TOKEN with real JWT)
curl -X GET http://localhost:4000/auth/profile \
  -H "Authorization: Bearer ACCESS_TOKEN"

🛠 Tech Stack

NestJS

Prisma

JWT

bcrypt

SendGrid
```
