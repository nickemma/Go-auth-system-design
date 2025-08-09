# Complete Auth System API Testing Guide

## Prerequisites
1. Update your Twilio credentials in .env file
2. Start the services: docker-compose up --build
3. Check health: GET http://localhost:8080/health

### 1. User Registration Flow
Register User

```bash
POST http://localhost:8080/api/v1/auth/register
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "password123",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890"
}
```

### Verify email (use the OTP sent to email)
```bash
POST http://localhost:8080/api/v1/auth/verify-email
Content-Type: application/json

{
  "code": "123456"  // Check your email for the code
}
```

### 2. Phone Verification Flow (Protected Routes)
Login First

```bash
POST http://localhost:8080/api/v1/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "password123"
}
```
### Update Phone Number (if needed)

```bash
POST http://localhost:8080/api/v1/phone/update
Authorization: Bearer YOUR_JWT_TOKEN
Content-Type: application/json

{
  "phone_number": "+1234567890"
}
```

### Send Phone Verification SMS
```bash
POST http://localhost:8080/api/v1/phone/send-verification
Authorization: Bearer YOUR_JWT_TOKEN
Content-Type: application/json
```
### Verify Phone Number
```bash
POST http://localhost:8080/api/v1/phone/verify
Authorization: Bearer YOUR_JWT_TOKEN
Content-Type: application/json

{
  "code": "123456"  // SMS code received
}
```
### 3. MFA Setup Flow
Setup MFA (Get QR Code & Backup Codes)

```bash
POST http://localhost:8080/api/v1/mfa/setup
Authorization: Bearer YOUR_JWT_TOKEN
Content-Type: application/json

{
  "method": "authenticator"  // or "sms"
}
```
### Enable MFA (Verify TOTP)

```bash
POST http://localhost:8080/api/v1/mfa/enable
Authorization: Bearer YOUR_JWT_TOKEN
Content-Type: application/json

{
  "totp_code": "123456"  // From authenticator app
}
```
### 4. MFA Login Flow
Login (Returns temp token if MFA enabled)

```bash
POST http://localhost:8080/api/v1/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "password123"
}

Response:
{
  "success": true,
  "requires_mfa": true,
  "temp_token": "eyJ...",
  "mfa_methods": ["authenticator", "sms", "backup_code"]
}
```

### Send SMS MFA Code (Optional)

```bash
POST http://localhost:8080/api/v1/auth/send-mfa-code
Content-Type: application/json

{
  "temp_token": "eyJ...",
  "method": "sms"
}
```
### Verify MFA (Complete Login)

```bash
POST http://localhost:8080/api/v1/auth/verify-mfa
Content-Type: application/json

{
  "temp_token": "eyJ...",
  "code": "123456",
  "method": "sms"  // or "authenticator" or "backup_code"
}

Response:
{
  "success": true,
  "token": "eyJ...",  // Final JWT token
  "user": { ... }
}
```

### 5. Password Reset Flow
Request Password Reset

```bash
POST http://localhost:8080/api/v1/auth/forgot-password
Content-Type: application/json

{
  "email": "test@example.com"
}
```
### Reset Password

```bash
POST http://localhost:8080/api/v1/auth/reset-password
Content-Type: application/json

{
  "token": "reset_token_from_email",
  "new_password": "newpassword123"
}
```
### 6. Get user profile (use token from login response)
```bash
GET http://localhost:8080/api/v1/mfa/enable
Authorization: Bearer YOUR_JWT_TOKEN
Content-Type: application/json
```

### 7. Change password
```bash
POST http://localhost:8080/api/v1/change-password \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "securepassword123",
    "new_password": "newsecurepassword456"
  }'
```

### Health Check
Check Service Status

```bash
GET http://localhost:8080/health

Response:
{
  "status": "ok",
  "sms_enabled": true,
  "twilio_config": true
}
```
Testing Tips

- **Phone Number Format:** Always use international format with country code (+1234567890)
- **SMS Delivery:** Check your phone for SMS codes (may take 1-2 minutes)
- **Rate Limiting:** Wait between requests if you hit rate limits
- **Token Expiry:** Temp tokens expire in 10 minutes, regular JWT tokens in 24 hours
- **MFA Methods:** Ensure phone is verified before SMS MFA becomes available