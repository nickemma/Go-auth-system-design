# Authentication System with Go, Gin, PostgreSQL, and DDD

A comprehensive authentication system built with Go, Gin framework, PostgreSQL database, following Domain-Driven Design (DDD) principles and repository pattern.

## Features

- **User Registration & Login**: Secure user registration and authentication
- **Email Verification**: OTP-based email verification system
- **JWT Authentication**: JSON Web Token based authentication
- **2FA/MFA Support**: Time-based One-Time Password (TOTP) support
- **Session Management**: Secure session handling
- **Password Security**: bcrypt password hashing
- **Clean Architecture**: DDD with repository pattern
- **Database**: PostgreSQL with proper migrations

## Project Structure

```
## Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd auth-system
   ```

2. **Install dependencies**
   ```bash
   go mod tidy
   ```

3. **Setup PostgreSQL database**
   ```bash
   createdb authdb
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your actual values
   ```

5. **Run the application**
   ```bash
   go run cmd/main.go
   ```
## Database Schema

The system uses the following PostgreSQL tables:

- **users**: User account information
- **otps**: One-time passwords for verification
- **sessions**: User session management

## Security Features

- Password hashing with bcrypt
- JWT token authentication
- Email verification with OTP
- Time-based One-Time Password (TOTP) for MFA
- Session management
- Secure password requirements
- Token expiration handling

## Environment Variables

- `PORT`: Server port (default: 8080)
- `DATABASE_URL`: PostgreSQL connection string
- `JWT_SECRET`: Secret key for JWT tokens
- `SMTP_HOST`: SMTP server host
- `SMTP_PORT`: SMTP server port
- `SMTP_USERNAME`: SMTP username
- `SMTP_PASSWORD`: SMTP password
- `SMTP_FROM`: From email address

## Dependencies

- **Gin**: HTTP web framework
- **PostgreSQL**: Database
- **JWT-Go**: JWT token handling
- **bcrypt**: Password hashing
- **TOTP**: Time-based OTP
- **Gomail**: Email sending
- **UUID**: Unique identifiers

## License