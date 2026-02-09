package com.example.ApiGateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * API Gateway Application for JobHub Microservices
 * 
 * This service acts as a centralized entry point for all client requests,
 * handling routing, authentication, rate limiting, and cross-cutting concerns.
 */
@SpringBootApplication
public class ApiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }
}
