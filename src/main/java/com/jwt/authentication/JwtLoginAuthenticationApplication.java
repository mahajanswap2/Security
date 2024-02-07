package com.jwt.authentication;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtLoginAuthenticationApplication {

	public static Logger logger = LogManager.getLogger(JwtLoginAuthenticationApplication.class);
	public static void main(String[] args) {
		SpringApplication.run(JwtLoginAuthenticationApplication.class, args);
		logger.info("--------------------Application Started--------------------");
		System.out.println("--------------------Application Started--------------------");
	}

}
