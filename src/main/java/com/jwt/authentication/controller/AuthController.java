package com.jwt.authentication.controller;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import com.jwt.authentication.entities.User;
import com.jwt.authentication.models.JwtRequest;
import com.jwt.authentication.models.JwtResponse;
import com.jwt.authentication.security.JwtHelper;
import com.jwt.authentication.services.UserService;


import java.util.Date;

import javax.crypto.SecretKey;

@RestController
@CrossOrigin("*")
@RequestMapping("/auth")
public class AuthController {
	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private JwtHelper jwtHelper;
	@Autowired
	private UserService userService;


	public AuthController(
	        UserDetailsService userDetailsService,
	        AuthenticationManager authenticationManager,
	        JwtHelper jwtHelper,
	        UserService userService
	) {
	    this.userDetailsService = userDetailsService;
	    this.authenticationManager = authenticationManager;
	    this.jwtHelper = jwtHelper;
	    this.userService = userService;
	}
    
    private Logger logger = LogManager.getLogger(AuthController.class);

    // Replace with your provided secret key
    private static final String SECRET_KEY = "zi9E2qvtQc1fa4NSlUPhoaDLaRJDu3SO";

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest request) {
        try {
            this.doAuthenticate(request.getEmail(), request.getPassword());
            UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
         //   String token = this.generateTokens(userDetails);
            String token =createToken(userDetails);
           // String decoetoken  = decodeToken(token);
            String decoetoken  = verifyToken(token);
            logger.info("decoetoken generated-------->>>" + decoetoken);
            logger.info("--------token generated--------" + token);

            JwtResponse response = JwtResponse.builder()
                    .jwtToken(token)
                    .username(userDetails.getUsername()).build();
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }
   
	private String createToken(UserDetails userDetails) {
        // Create a secret key from the provided string
        SecretKey secretKey = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

        // Build the JWT
        String token = Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hour from now
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();

        return token;
    }

	private String verifyToken(String token) {
	    // Create a secret key from the provided string
	    SecretKey secretKey = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

	    try {
	        // Parse and verify the token
	        Jws<Claims> claimsJws = Jwts.parserBuilder()
	                .setSigningKey(secretKey)
	                .build()
	                .parseClaimsJws(token);

	        // Token is valid
	        System.out.println("Token verification succeeded.");
	        
	        // Return a success message or additional information
	        return "Token verification succeeded. User: " + claimsJws.getBody().getSubject();

	    } catch (Exception e) {
	        // Token is not valid
	        System.out.println("Token verification failed.");
	        e.printStackTrace();

	        // Return an error message or additional information
	        return "Token verification failed. Error: " + e.getMessage();
	    }
	}
    private String generateTokens(UserDetails userDetails) {

        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
                .signWith(secretKey)
                .compact();
    }
  
    public String decodeToken(String token) {
        try {
        	  Claims claims = Jwts.parserBuilder()
                      .setSigningKey(SECRET_KEY.getBytes())
                      .build()
                      .parseClaimsJws(token)
                      .getBody();

            // Retrieve the decoded claims
              String decodedClaims = claims.toString();

            // Convert the claims to a string representation
           

            // Print the decoded claims on the console
            System.out.println("Decoded Token Claims: " + decodedClaims);

            // Return the decoded claims as a string
            return decodedClaims;
        } catch (Exception e) {
            // Print the error message on the console
            System.err.println("Invalid Token");

            // Return an error message
            return "Invalid Token";
        }
    }

    private void doAuthenticate(String email, String password) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);
        authenticationManager.authenticate(authenticationToken);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<String> exceptionHandler() {
        return new ResponseEntity<>("Credentials Invalid !!", HttpStatus.UNAUTHORIZED);
    }

    @PostMapping("/create-user")
    public ResponseEntity<User> createUser(@RequestBody User user) {
        User createdUser = userService.createUser(user);
        return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
    }
}
