package com.jwt.authentication.services;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jwt.authentication.entities.User;
import com.jwt.authentication.repository.UserRepository;

@Service
public class UserServiceImpl implements UserService{
	public List<User> store = new ArrayList<>();
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	public List<User> getUsers() {
		// TODO Auto-generated method stub
		return userRepository.findAll();
	}

	@Override
	public User createUser(User user) {
		// TODO Auto-generated method stub
		user.setUserId(UUID.randomUUID().toString());
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userRepository.save(user);
	}
	
//	public UserServiceImpl() {
//		store.add(new User(UUID.randomUUID().toString(),"Vikas Yadav","yadavikas004@gmail.com"));
//		store.add(new User(UUID.randomUUID().toString(),"Kareena Yadav","yada9812kareena@gmail.com"));
//		store.add(new User(UUID.randomUUID().toString(),"Harsh Yadav","yada9812harsh@gmail.com"));
//		store.add(new User(UUID.randomUUID().toString(),"Ramrathi Yadav","yadavramrathi088@gmail.com"));
//	}
	

}
