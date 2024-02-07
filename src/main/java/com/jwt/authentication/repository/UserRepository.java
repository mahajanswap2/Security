package com.jwt.authentication.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jwt.authentication.entities.User;

public interface UserRepository extends JpaRepository<User, String> {
	public Optional<User> findByEmail(String email);
}
