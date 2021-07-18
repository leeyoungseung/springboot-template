package com.pj.template.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.CorsFilter;

import com.pj.template.auth.filter.JwtAuthenticationFilter;
import com.pj.template.auth.filter.JwtAuthorizationFilter;
import com.pj.template.auth.repository.UserRepository;
import com.pj.template.auth.util.JwtUtil;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final CorsFilter corsFilter;
	private final UserRepository userRepository;
	private final JwtUtil jwtUtil;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();

		http.sessionManagement()
		    .sessionCreationPolicy(SessionCreationPolicy.STATELESS) 
		    .and().addFilter(corsFilter)
			.formLogin().disable()
			.httpBasic().disable() 
			.addFilter(new JwtAuthenticationFilter(authenticationManager(), userRepository, jwtUtil))
			.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository, jwtUtil))
			.authorizeRequests()
			    .antMatchers("/api/hello").permitAll()
			    .antMatchers("/api/signup").permitAll()
			    .antMatchers("/api/v1/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
			    .antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
			    .antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')")
			    .anyRequest().permitAll();
	}
}
