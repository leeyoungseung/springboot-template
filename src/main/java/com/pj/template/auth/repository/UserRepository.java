package com.pj.template.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.pj.template.auth.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByUsername(String username);
	Optional<User> findByRefreshToken(String refreshToken);
}
