package com.eazybytes.eazystore.util;


import com.eazybytes.eazystore.constants.ApplicationConstants;
import com.eazybytes.eazystore.entity.Customer;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtUtil {
    private final Environment env;
     public String generateJwtToken(Authentication authentication){
         try {
             String secret=env.getProperty(ApplicationConstants.JWT_SECRET_KEY,ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
             
             // Validate secret key length
             if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
                 log.error("JWT secret key is too short or null. Required: 32 bytes, Actual: {} bytes", 
                     secret != null ? secret.getBytes(StandardCharsets.UTF_8).length : 0);
                 throw new IllegalArgumentException("JWT secret key must be at least 32 bytes (256 bits)");
             }
             
             log.debug("JWT Secret key length: {} bytes", secret.getBytes(StandardCharsets.UTF_8).length);
             SecretKey secretKey= Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
             Customer fetchedCustomer= (Customer) authentication.getPrincipal();
             
             String jwt= Jwts.builder().issuer("EasyBank").subject("JWT Token").
                     claim("username",fetchedCustomer.getName())
                     .claim("email",fetchedCustomer.getEmail())
                     .claim("mobileNumber",fetchedCustomer.getMobileNumber())
                     .issuedAt(new java.util.Date())
                     .expiration(new java.util.Date((new java.util.Date()).getTime()+60*60*1000))
                     .signWith(secretKey).compact();
             
             log.debug("JWT token generated successfully for user: {}", fetchedCustomer.getName());
             return jwt;
         } catch (Exception e) {
             log.error("Error generating JWT token: {}", e.getMessage(), e);
             throw new RuntimeException("Failed to generate JWT token: " + e.getMessage(), e);
         }
     }
}
