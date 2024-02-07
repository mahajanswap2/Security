package com.jwt.authentication.services;

import java.util.List;

import com.jwt.authentication.entities.User;

public interface UserService {

	public List<User> getUsers();

	public User createUser(User user);

}
