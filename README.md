# API Gateway - JobHub

API Gateway for JobHub Microservices Architecture

## Overview

This API Gateway serves as the **single entry point** for all client requests to the JobHub microservices. It handles:

- **JWT Authentication & Authorization** - Validates tokens and forwards user info to downstream services
- **Request Routing** - Routes requests to appropriate microservices
- **Cross-Origin Resource Sharing (CORS)** - Configured for React frontend
- **Rate Limiting Ready** - Structure prepared for rate limiting
- **Circuit Breaking Ready** - Prepared for resilience patterns

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Frontend (React)                        │
│                        :3000                                 │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   API Gateway (Port 8084)                    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  • JWT Validation                                    │    │
│  │  • Route to Services                                │    │
│  │  • CORS Configuration                                │    │
│  │  • Forward User Headers (X-User-Id, X-User-Email) │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
          ▼               ▼               ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐
│ Auth Service │  │  App Service│  │ Notification Service│
│   (8081)     │  │    (8083)   │  │      (8082)         │
└─────────────┘  └─────────────┘  └─────────────────────┘
```

## Service Ports

| Service | Port | Route on Gateway |
|---------|------|------------------|
| API Gateway | **8084** | Main entry point |
| Auth Service | 8081 | `/api/v1/auth/**`, `/api/v1/profile/**`, `/api/v1/skills/**`, `/api/v1/experience/**`, `/api/v1/education/**` |
| Application Service | 8083 | `/api/v1/applications/**`, `/api/v1/jobs/**` |
| Notification Service | 8082 | Not exposed (Kafka-only) |

## API Endpoints

### Public Endpoints (No JWT Required)

```
POST   /api/v1/auth/login              - User login
POST   /api/v1/auth/register           - User registration
POST   /api/v1/auth/forgot-password    - Request password reset
POST   /api/v1/auth/refresh-token     - Refresh access token
POST   /api/v1/auth/verify-email      - Verify email address
```

### Protected Endpoints (JWT Required)

All other endpoints require a valid JWT token in the `Authorization` header:

```
Authorization: Bearer <your-jwt-token>
```

#### Profile & Skills
```
GET    /api/v1/profile                 - Get user profile
PUT    /api/v1/profile                 - Update profile
GET    /api/v1/skills                  - Get user skills
POST   /api/v1/skills                  - Add skill
PUT    /api/v1/skills/{id}            - Update skill
DELETE /api/v1/skills/{id}            - Delete skill
GET    /api/v1/experience              - Get user experience
POST   /api/v1/experience              - Add experience
PUT    /api/v1/experience/{id}        - Update experience
DELETE /api/v1/experience/{id}        - Delete experience
GET    /api/v1/education               - Get user education
POST   /api/v1/education               - Add education
PUT    /api/v1/education/{id}        - Update education
DELETE /api/v1/education/{id}        - Delete education
```

#### Applications &    /api/v1/applications            - Get user's applications Jobs
```
GET
POST   /api/v1/applications            - Submit application
GET    /api/v1/applications/{id}       - Get application details
PUT    /api/v1/applications/{id}/withdraw - Withdraw application
GET    /api/v1/applications/stats      - Get application stats
POST   /api/v1/jobs/{id}/save          - Save job
DELETE /api/v1/jobs/{id}/unsave        - Remove saved job
GET    /api/v1/jobs/saved              - Get saved jobs
GET    /api/v1/jobs/recommendations    - Get AI recommendations
POST   /api/v1/jobs/recommendations/feedback - Give feedback
```

## Headers Forwarded to Downstream Services

The API Gateway extracts user information from the JWT and forwards it to downstream services:

| Header | Description |
|--------|-------------|
| `X-User-Id` | User's UUID |
| `X-User-Email` | User's email address |
| `X-User-Type` | User's role (USER, ADMIN, etc.) |
| `X-User-Name` | User's username |

## Configuration

### Environment Variables

```bash
# JWT Configuration
JWT_SECRET=your-256-bit-secret-key-for-jwt-signing-must-be-at-least-256-bits-long
JWT_EXPIRATION=86400000  # 24 hours in milliseconds

# Server Configuration
SERVER_PORT=8084
```

### application.yml

The gateway configuration is in [`src/main/resources/application.yml`](src/main/resources/application.yml).

## Running with Docker

### Option 1: Full Stack (Recommended)

```bash
# From the Api-Gateway-JobHub directory
cd Api-Gateway-JobHub

# Start all services
docker-compose up -d

# Check logs
docker-compose logs -f api-gateway

# Stop all services
docker-compose down
```

### Option 2: Gateway Only

```bash
# Build the gateway
docker build -t jobhub-api-gateway .

# Run the gateway
docker run -p 8084:8084 \
  -e JWT_SECRET=your-secret-key \
  jobhub-api-gateway
```

### Option 3: Local Development

```bash
# Build and run with Maven
cd Api-Gateway-JobHub
./mvnw spring-boot:run

# Or
mvn spring-boot:run
```

## Health Check

The gateway provides health check endpoints:

```bash
# Basic health
curl http://localhost:8084/actuator/health

# Detailed health
curl http://localhost:8084/actuator/health/details

# Gateway-specific metrics
curl http://localhost:8084/actuator/metrics/gateway.requests
```

## Frontend Integration

Update your React environment file:

```env
# .env
REACT_APP_API_URL=http://localhost:8084/api/v1
```

### Example API Call

```typescript
// Login
const response = await fetch('http://localhost:8084/api/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password })
});
const { token } = await response.json();

// Save token
localStorage.setItem('token', token);

// Subsequent requests (automatically authenticated)
const profileResponse = await fetch('http://localhost:8084/api/v1/profile', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

## JWT Token Structure

The gateway expects JWT tokens with the following claims:

```json
{
  "sub": "username@email.com",
  "userId": "uuid-here",
  "userType": "USER",
  "email": "user@email.com",
  "exp": 1234567890,
  "iat": 1234567890
}
```

## Security Notes

1. **JWT Secret** - Must match the Authentication Service's JWT secret
2. **HTTPS** - In production, enable HTTPS/TLS
3. **Rate Limiting** - Implement rate limiting for production
4. **CORS** - Configure allowed origins for production

## Troubleshooting

### 401 Unauthorized
- Check if token is valid and not expired
- Ensure `Authorization` header format is `Bearer <token>`

### 403 Forbidden
- User may not have permission for this endpoint
- Check `X-User-Type` header

### Route Not Found
- Verify the path matches a configured route
- Check gateway logs for routing information

### Services Not Reachable
- Ensure downstream services are running
- Check network connectivity between containers
