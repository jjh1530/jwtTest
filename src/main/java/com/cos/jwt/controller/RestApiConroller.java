package com.cos.jwt.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

@RestController
public class RestApiConroller {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@GetMapping("/")
	public String home() {
		return "home";
	}
	@PostMapping("/")
	public String token() {
		return "tokebn";
	}
	
	@GetMapping("admin/users")
	public List<User> users() {
		return userRepository.findAll();
	}
	
	@GetMapping("join")
	public String join() {
		User user = new User();
		user.setUsername("wogns");
		user.setPassword(bCryptPasswordEncoder.encode("1234"));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입완료";
	}
	
	@GetMapping("/api/v1/user")
	public String user() {
		return"user";
	}
	
	@GetMapping("/api/v1/manager")
	public String manager() {
		return"user";
	}
	
	@GetMapping("/api/v1/admin")
	public String admin() {
		return"user";
	}
	
	
}
