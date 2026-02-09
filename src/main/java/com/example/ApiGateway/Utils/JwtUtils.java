package com.example.ApiGateway.Utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.function.Function;

/**
 * Utility class for JWT token operations
 * Uses RSA public key from JKS keystore to validate tokens
 */
@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${jwt.keystore.path}")
    private String keystorePath;

    @Value("${jwt.keystore.password}")
    private String keystorePassword;

    @Value("${jwt.key.alias}")
    private String keyAlias;

    private PublicKey publicKey;

    /**
     * Get the public key from the JKS keystore
     */
    private PublicKey getPublicKey() {
        if (publicKey == null) {
            try {
                KeyStore keyStore = KeyStore.getInstance("JKS");
                var resourceAsStream = getClass().getClassLoader().getResourceAsStream(keystorePath);
                if (resourceAsStream == null) {
                    logger.warn("Keystore not found at: {}, falling back to HMAC", keystorePath);
                    return null;
                }
                keyStore.load(resourceAsStream, keystorePassword.toCharArray());

                Certificate cert = keyStore.getCertificate(keyAlias);
                if (cert == null) {
                    logger.warn("Certificate not found for alias: {}, falling back to HMAC", keyAlias);
                    return null;
                }
                publicKey = cert.getPublicKey();
                logger.info("Successfully loaded public key from keystore");
            } catch (Exception e) {
                logger.error("Failed to load keystore: {}. Falling back to HMAC secret.", e.getMessage());
                return null;
            }
        }
        return publicKey;
    }

    /**
     * Get the signing key (HMAC fallback)
     */
    private SecretKey getSigningKey() {
        String jwtSecret = System.getenv("JWT_SECRET");
        if (jwtSecret == null || jwtSecret.isEmpty()) {
            jwtSecret = "your-256-bit-secret-key-for-jwt-signing-must-be-at-least-256-bits-long";
        }
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Extract the username (subject) from the token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract the userId claim from the token
     */
    public String extractUserId(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("userId", String.class);
    }

    /**
     * Extract the userType (role) claim from the token
     */
    public String extractUserType(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("userType", String.class);
    }

    /**
     * Extract the email claim from the token
     */
    public String extractEmail(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("email", String.class);
    }

    /**
     * Extract the expiration date from the token
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extract a specific claim from the token
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from the token
     */
    private Claims extractAllClaims(String token) {
        PublicKey pk = getPublicKey();
        
        if (pk != null) {
            // Use RSA public key
            return Jwts.parser()
                    .verifyWith(pk)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } else {
            // Fallback to HMAC
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        }
    }

    /**
     * Check if the token has expired
     */
    public boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Validate the token
     * Returns true if the token is valid, false otherwise
     */
    public boolean validateToken(String token) {
        try {
            extractAllClaims(token);
            return !isTokenExpired(token);
        } catch (Exception e) {
            logger.error("JWT validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Validate token for a specific username
     */
    public boolean validateToken(String token, String username) {
        try {
            final String tokenUsername = extractUsername(token);
            return (tokenUsername.equals(username) && !isTokenExpired(token));
        } catch (Exception e) {
            logger.error("JWT validation failed for username: {}", e.getMessage());
            return false;
        }
    }
}
