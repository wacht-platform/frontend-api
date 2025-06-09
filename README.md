# Wacht Frontend API

A high-performance Go-based customer-facing API that powers end-user applications built with the Wacht development toolkit. This API provides configurable functionality to tenant users based on platform configuration.

## 🚀 Overview

The Wacht Frontend API is a customer-facing backend that serves end users of applications built on the Wacht platform. Depending on the tenant configuration, it provides various functionalities including authentication, user management, organization features, and custom business logic to support the specific needs of each tenant's application.

## ✨ Features

- **Configurable Authentication**: Tenant-specific user authentication with JWT tokens, OAuth2 integration, and optional 2FA
- **Multi-tenant Architecture**: Isolated user data and functionality per tenant organization
- **User Management**: Complete user lifecycle management for tenant applications
- **Workspace Integration**: User workspace access and collaboration features
- **Flexible API Endpoints**: Configurable endpoints based on tenant requirements and feature flags
- **Real-time Operations**: Redis-backed caching and session management for optimal performance
- **Enterprise Security**: Argon2 password hashing, secure token management, and tenant data isolation

## 🛠 Tech Stack

- **Framework**: [Fiber v2](https://gofiber.io/) - Express-inspired web framework
- **Database**: PostgreSQL with [GORM](https://gorm.io/) ORM
- **Cache**: Redis for session management and caching
- **Authentication**: JWT with [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx)
- **Validation**: [go-playground/validator](https://github.com/go-playground/validator)
- **Password Hashing**: Argon2 for secure password storage
- **2FA**: TOTP support with [pquerna/otp](https://github.com/pquerna/otp)
- **OAuth2**: OAuth integration

## 📋 Prerequisites

- Go 1.23.4 or higher
- PostgreSQL 12+
- Redis 6+
- Git

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone <repository-url>
cd wacht-frontend-api
```

### 2. Install dependencies

```bash
go mod download
```

### 3. Environment Configuration

Create a `.env` file in the root directory:

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=wacht_db

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=24h

# OAuth2 Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Server Configuration
PORT=3000
ENVIRONMENT=development
```

### 4. Run the application

```bash
go run main.go
```

The API will be available at `http://localhost:3000`

## 📁 Project Structure

```
wacht-frontend-api/
├── config/          # Configuration management
├── database/        # Database connection and migrations
├── handler/         # HTTP request handlers
├── middleware/      # Custom middleware functions
├── model/          # Database models and schemas
├── router/         # Route definitions
├── service/        # Business logic layer
├── utils/          # Utility functions
├── main.go         # Application entry point
├── go.mod          # Go module dependencies
└── Dockerfile      # Container configuration
```

## 🔧 Development

### Running in Development Mode

```bash
# Install air for hot reloading (optional)
go install github.com/cosmtrek/air@latest

# Run with hot reloading
air

# Or run normally
go run main.go
```

### Building for Production

```bash
# Build binary
go build -o wacht-api main.go

# Run binary
./wacht-api
```

### Docker Deployment

```bash
# Build Docker image
docker build -t wacht-frontend-api .

# Run container
docker run -p 3000:3000 --env-file .env wacht-frontend-api
```

## 📚 API Documentation

The API provides tenant-configurable endpoints for:

- **Authentication**: `/auth/*` - User login, signup, OAuth, and 2FA (configurable per tenant)
- **User Profiles**: `/users/*` - User profile management and preferences
- **Organization Features**: `/organizations/*` - Tenant-specific organization functionality
- **Workspace Access**: `/workspaces/*` - User workspace interactions and collaboration
- **Custom Endpoints**: Tenant-specific business logic endpoints based on configuration

### Example API Calls

```bash
# Health check
curl http://localhost:3000/health

# User registration (if enabled for tenant)
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: tenant-123" \
  -d '{"email":"user@example.com","password":"securepassword"}'

# User login
curl -X POST http://localhost:3000/auth/signin \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: tenant-123" \
  -d '{"email":"user@example.com","password":"securepassword"}'

# Get user profile
curl -X GET http://localhost:3000/users/profile \
  -H "Authorization: Bearer <jwt-token>" \
  -H "X-Tenant-ID: tenant-123"
```

## 🧪 Testing

```bash
# Run tests
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

### Code Style

- Follow Go conventions and use `gofmt`
- Write meaningful commit messages
- Add tests for new features
- Update documentation as needed

## 📄 License

This project is licensed under the terms specified in the [LICENSE.md](LICENSE.md) file.

## 🆘 Support

For support and questions:

- Create an issue in this repository
- Contact the development team
- Check the documentation

## 🔗 Related Projects

- [Wacht React Components](../wacht-react) - Shared UI components and hooks
- Wacht Platform - Main platform repository

---

Built with ❤️ by the Wacht team for enterprise-grade application development.
