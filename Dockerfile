# Build stage
FROM maven:3.9.5-eclipse-temurin-17 AS builder

WORKDIR /app

# Copy pom.xml first for dependency caching
COPY pom.xml ./
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN mvn clean package -DskipTests -B

# Runtime stage
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Create non-root user for security
RUN addgroup -S jobhub && adduser -S jobhub -G jobhub
USER jobhub

# Copy the built artifact from builder stage
COPY --from=builder /app/target/*.jar app.jar

# Expose the gateway port
EXPOSE 8084

# Environment variables (can be overridden)
ENV JWT_SECRET=your-256-bit-secret-key-for-jwt-signing-must-be-at-least-256-bits-long
ENV JWT_EXPIRATION=86400000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8084/actuator/health || exit 1

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
