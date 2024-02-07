package com.jwt.authentication.controller;



import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class TokenExample {

    // Replace this with your secret key
    private static final String SECRET_KEY = "zi9E2qvtQc1fa4NSlUPhoaDLaRJDu3SO";

    public static void main(String[] args) {
        try {
            // Create a JWT
            String token = createToken("subject123");

            // Print the generated token
            System.out.println("Generated Token: " + token);

            // Verify the token
            verifyToken(token);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String createToken(String subject) {
        // Create a secret key from the provided string
        SecretKey secretKey = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

        // Build the JWT
        String token = Jwts.builder()
                .setSubject(subject)
                .setExpiration(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hour from now
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();

        return token;
    }

    private static void verifyToken(String token) {
        // Create a secret key from the provided string
        SecretKey secretKey = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

        try {
            // Parse and verify the token
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);

            // Token is valid
            System.out.println("Token verification succeeded.");

        } catch (Exception e) {
            // Token is not valid
            System.out.println("Token verification failed.");
            e.printStackTrace();
        }
    }
}
