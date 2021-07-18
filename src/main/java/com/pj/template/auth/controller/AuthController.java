package com.pj.template.auth.controller;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.pj.template.auth.dto.LoginRequestDTO;
import com.pj.template.auth.model.User;
import com.pj.template.auth.repository.UserRepository;
import com.pj.template.auth.service.PrincipalDetail;
import com.pj.template.auth.util.JwtUtil;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class AuthController {

	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private final UserRepository userRepository;
	
	@Autowired
	private JwtUtil jwtUtil;
    
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
	
	@PostMapping("/signup")
	public String signup(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "signup complete";
	}
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginRequestDTO dto)
			throws Exception {

		
		// (5) 로그인 결과 전송
		return ResponseEntity.ok(null);
	}
	
	@GetMapping("/api/v1/user")
	public String user(Authentication authentication) {
		PrincipalDetail principalDetails = (PrincipalDetail) authentication.getPrincipal();
		System.out.println("authentication : "+principalDetails.getUsername());
		return "user";
	}

	@GetMapping("/api/v1/manager")
	public String manager() {
		return "manager";
	}
	
	@GetMapping("/api/v1/admin")
	public String admin() {
		return "admin";
	}
	
}
