# Wacht Frontend API

Customer-facing API for applications built with Wacht. This is the backend that powers your end-user applications - handling authentication, user management, organizations, and all the customer-facing functionality.

Wacht is a development toolkit that helps you build enterprise apps fast - authentication, user management, organizations, AI tools, and analytics are all included.

This API serves your actual customers and users, providing configurable functionality based on your deployment settings from the Wacht console.

## What's included

**Authentication stuff**
- User signup/signin with sessions
- JWT tokens and OAuth2 integration
- 2FA/TOTP support
- Social logins (configurable per deployment)
- Secure password hashing with Argon2

**User management**
- Complete user lifecycle management
- User profiles and preferences
- Email verification and password reset
- User analytics and activity tracking

**B2B features**
- Organizations and workspaces
- Multi-tenant architecture with data isolation
- Custom roles and permissions
- Member invitations and management

**Infrastructure**
- Redis-backed sessions and caching
- Email integration
- File uploads and CDN support
- Health checks and monitoring
- Deployment-specific configuration

## Tech stack

- Go 1.23.4 with Fiber v2
- PostgreSQL with GORM
- Redis for sessions and caching
- JWT with lestrrat-go/jwx
- Argon2 for password hashing
- AWS SDK for cloud services

## Setup

**1. Clone and setup**

```bash
git clone <repository-url>
cd wacht-frontend-api
go mod download
```

**2. Environment variables**

Create a `.env` file:

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=wacht_db

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# JWT
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=24h

# OAuth2
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# AWS (for file uploads)
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1

# Application
PORT=3000
ENVIRONMENT=development
```

**3. Run it**

```bash
# Development
go run main.go

# Production
go build -o wacht-frontend-api
./wacht-frontend-api
```

API runs on `http://localhost:3000`

## Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific test
go test ./handler -v
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Licensed under GNU Affero General Public License v3.0 only (AGPL-3.0-only). See [LICENSE.md](LICENSE.md).

## 🔗 Related Projects

- [Wacht Console](https://github.com/wacht-platform/console) - React frontend for managing deployments

## 📞 Support

For support and questions, please open an issue in the GitHub repository.
