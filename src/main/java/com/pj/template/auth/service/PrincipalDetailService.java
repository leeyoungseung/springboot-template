package com.pj.template.auth.service;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.pj.template.auth.model.User;
import com.pj.template.auth.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {
	
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<User> data = userRepository.findByUsername(username);
		User userEntity = data.get();
		System.out.println("loadUserByUsername userEntity : "+userEntity);
		return new PrincipalDetail(userEntity);
	}
}
