# 1. Register a new user
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "securepassword123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

# 2. Verify email (use the OTP sent to email)
```bash
curl -X POST http://localhost:8080/api/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "code": "123456"
  }'
```

# 3. Login user
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "securepassword123"
  }'
```

# 4. Get user profile (use token from login response)
```bash
curl -X GET http://localhost:8080/api/v1/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

# 5. Setup MFA
```bash
curl -X POST http://localhost:8080/api/v1/mfa/setup \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE" \
  -H "Content-Type: application/json"
```

# 6. Enable MFA (use TOTP code from authenticator app)
```bash
curl -X POST http://localhost:8080/api/v1/mfa/enable \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "totp_code": "123456"
  }'
```

# 7. Login with MFA
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "securepassword123",
    "totp_code": "123456"
  }'
```

# 8. Verify MFA (if using temp token flow)
```bash
curl -X POST http://localhost:8080/api/v1/auth/verify-mfa \
  -H "Content-Type: application/json" \
  -d '{
    "temp_token": "TEMP_TOKEN_FROM_LOGIN",
    "totp_code": "123456"
  }'
```

# 9. Forgot password
```bash
curl -X POST http://localhost:8080/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com"
  }'
```

# 10. Reset password
```bash
curl -X POST http://localhost:8080/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "code": "123456",
    "new_password": "newsecurepassword123"
  }'
```

# 11. Logout
```bash
curl -X POST http://localhost:8080/api/v1/logout \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```