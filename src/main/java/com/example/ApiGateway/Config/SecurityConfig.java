package com.example.ApiGateway.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import org.springframework.http.HttpMethod;

/**
 * Security Configuration for API Gateway
 * 
 * Configures:
 * - CSRF disabled (using JWT tokens)
 * - Public endpoints access
 * - OPTIONS requests allowed
 * - Authentication requirements for protected endpoints
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    /**
     * Configure the security filter chain
     */
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            // Disable CSRF for API gateway (we're using JWT tokens)
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            
            // Configure authorization rules
            .authorizeExchange(exchanges -> exchanges
                // Allow all OPTIONS requests (CORS preflight)
                .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                
                // Public endpoints - no authentication required
                .pathMatchers("/api/v1/auth/login").permitAll()
                .pathMatchers("/api/v1/auth/register").permitAll()
                .pathMatchers("/api/v1/auth/forgot-password").permitAll()
                .pathMatchers("/api/v1/auth/reset-password").permitAll()
                .pathMatchers("/api/v1/auth/refresh-token").permitAll()
                .pathMatchers("/api/v1/auth/verify-email").permitAll()
                .pathMatchers("/api/v1/auth/resend-verification").permitAll()
                
                // Health check endpoints
                .pathMatchers("/actuator/health").permitAll()
                .pathMatchers("/actuator/health/**").permitAll()
                .pathMatchers("/actuator/info").permitAll()
                .pathMatchers("/actuator").permitAll()
                
                // Error endpoint
                .pathMatchers("/error").permitAll()
                
                // All other endpoints require authentication
                .anyExchange().authenticated()
            )
            
            // Disable basic authentication
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            
            // Disable form login
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            
            // Build the security filter chain
            .build();
    }
}
