package com.example.ApiGateway.Filter;

import com.example.ApiGateway.Utils.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * JWT Authentication Filter for API Gateway
 * 
 * This filter:
 * 1. Validates JWT tokens from Authorization header
 * 2. Extracts user information from the token
 * 3. Forwards user info to downstream services via headers
 * 4. Allows public endpoints to bypass authentication
 */
@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String USER_EMAIL_HEADER = "X-User-Email";
    private static final String USER_TYPE_HEADER = "X-User-Type";
    private static final String USER_NAME_HEADER = "X-User-Name";

    private final JwtUtils jwtUtils;

    // Set of public endpoints that don't require authentication
    private static final Set<String> PUBLIC_ENDPOINTS = new HashSet<>();

    static {
        // Authentication endpoints
        PUBLIC_ENDPOINTS.add("/api/v1/auth/login");
        PUBLIC_ENDPOINTS.add("/api/v1/auth/register");
        PUBLIC_ENDPOINTS.add("/api/v1/auth/forgot-password");
        PUBLIC_ENDPOINTS.add("/api/v1/auth/reset-password");
        PUBLIC_ENDPOINTS.add("/api/v1/auth/refresh-token");
        PUBLIC_ENDPOINTS.add("/api/v1/auth/verify-email");
        PUBLIC_ENDPOINTS.add("/api/v1/auth/resend-verification");
        
        // Health check endpoints
        PUBLIC_ENDPOINTS.add("/actuator/health");
        PUBLIC_ENDPOINTS.add("/actuator/info");
        PUBLIC_ENDPOINTS.add("/actuator");
        
        // Error endpoint
        PUBLIC_ENDPOINTS.add("/error");
    }

    public JwtAuthenticationFilter(JwtUtils jwtUtils) {
        super(Config.class);
        this.jwtUtils = jwtUtils;
    }

    public static class Config {
        // Configuration properties can be added here if needed
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            // Skip authentication for public endpoints
            if (isPublicEndpoint(path)) {
                logger.debug("Public endpoint accessed: {}", path);
                return chain.filter(exchange);
            }

            // Get Authorization header
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            // Check if Authorization header is present
            if (authHeader == null) {
                logger.warn("Missing Authorization header for path: {}", path);
                return onError(exchange, "Missing Authorization header", HttpStatus.UNAUTHORIZED);
            }

            // Check if it starts with "Bearer "
            if (!authHeader.startsWith(BEARER_PREFIX)) {
                logger.warn("Invalid Authorization header format for path: {}", path);
                return onError(exchange, "Invalid Authorization header format", HttpStatus.UNAUTHORIZED);
            }

            // Extract and validate token
            String token = authHeader.substring(BEARER_PREFIX.length());

            if (token.isEmpty()) {
                logger.warn("Empty token for path: {}", path);
                return onError(exchange, "Empty token", HttpStatus.UNAUTHORIZED);
            }

            try {
                // Validate the token
                if (!jwtUtils.validateToken(token)) {
                    logger.warn("Invalid or expired token for path: {}", path);
                    return onError(exchange, "Invalid or expired token", HttpStatus.UNAUTHORIZED);
                }

                // Extract user information from the token
                String userId = jwtUtils.extractUserId(token);
                String userEmail = jwtUtils.extractEmail(token);
                String userType = jwtUtils.extractUserType(token);
                String userName = jwtUtils.extractUsername(token);

                logger.debug("Authenticated user: {} (ID: {}) for path: {}", userName, userId, path);

                // Forward user information to downstream services via headers
                ServerHttpRequest modifiedRequest = request.mutate()
                        .header(USER_ID_HEADER, userId != null ? userId : "")
                        .header(USER_EMAIL_HEADER, userEmail != null ? userEmail : "")
                        .header(USER_TYPE_HEADER, userType != null ? userType : "")
                        .header(USER_NAME_HEADER, userName != null ? userName : "")
                        .build();

                return chain.filter(exchange.mutate().request(modifiedRequest).build());

            } catch (Exception e) {
                logger.error("Error processing JWT token for path: {} - {}", path, e.getMessage());
                return onError(exchange, "Token validation failed: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
            }
        };
    }

    /**
     * Check if the given path is a public endpoint
     */
    private boolean isPublicEndpoint(String path) {
        // Check exact matches first
        if (PUBLIC_ENDPOINTS.contains(path)) {
            return true;
        }
        
        // Check if path starts with any public endpoint prefix
        for (String endpoint : PUBLIC_ENDPOINTS) {
            if (path.startsWith(endpoint)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Handle error response
     */
    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        
        String errorResponse = String.format(
                "{\"error\": \"%s\", \"status\": %d, \"path\": \"%s\"}",
                message,
                status.value(),
                exchange.getRequest().getURI().getPath()
        );
        
        return response.writeWith(Mono.just(response.bufferFactory().wrap(errorResponse.getBytes(StandardCharsets.UTF_8))));
    }
}
