package com.pj.template.auth.util;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Service
public class JwtUtil {
	
	private String salt;
	private String saltRefresh;
	private int jwtExpirationInMs;
	private int refreshExpirationDateInMs;
	private SignatureAlgorithm signatureAlgorithm;

	@Value("${jwt.secret}")
	public void setSalt(String salt) {
		this.salt = salt;
	}
	
	@Value("${jwt.secret-refresh}")
	public void setSaltRefresh(String saltRefresh) {
		this.saltRefresh = saltRefresh;
	}

	@Value("${jwt.expire-time}")
	public void setJwtExpirationInMs(int jwtExpirationInMs) {
		this.jwtExpirationInMs = jwtExpirationInMs;
	}

	@Value("${jwt.refresh-expire-time}")
	public void setRefreshExpirationDateInMs(int refreshExpirationDateInMs) {
		this.refreshExpirationDateInMs = refreshExpirationDateInMs;
	}
	
	@Value("${jwt.signatureAlgorithm}")
	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = SignatureAlgorithm.valueOf(signatureAlgorithm);
	}

	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();

		Collection<? extends GrantedAuthority> roles = userDetails.getAuthorities();

		if (roles.contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
			claims.put("isAdmin", true);
		}
		if (roles.contains(new SimpleGrantedAuthority("ROLE_MANAGER"))) {
			claims.put("isManager", true);
		}
		if (roles.contains(new SimpleGrantedAuthority("ROLE_USER"))) {
			claims.put("isUser", true);
		}

		return doGenerateToken(claims, userDetails.getUsername());
	}

	private String doGenerateToken(Map<String, Object> claims, String subject) {

		return Jwts.builder()
				.setClaims(claims)
				.setSubject(subject)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + (60 * 1000 * jwtExpirationInMs)))
				.signWith(signatureAlgorithm, salt)
				.compact();

	}

	public String generateRefreshToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		
		return doGenerateRefreshToken(claims, userDetails.getUsername() );
	}
	
	public String doGenerateRefreshToken(Map<String, Object> claims, String subject) {

		return Jwts.builder()
				.setClaims(claims)
				.setSubject(subject)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + (60 * 1000 * refreshExpirationDateInMs)))
				.signWith(signatureAlgorithm, saltRefresh)
				.compact();

	}

	public boolean validateToken(String authToken) {
		try {
			Jws<Claims> claims = Jwts.parser().setSigningKey(salt).parseClaimsJws(authToken);
			return true;
		} catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
			throw new BadCredentialsException("INVALID_CREDENTIALS", ex);
		} catch (ExpiredJwtException ex) {
			throw ex;
		}
	}
	
	public boolean validateRefreshToken(String refreshToken) {
		try {
			Jws<Claims> claims = Jwts.parser().setSigningKey(saltRefresh).parseClaimsJws(refreshToken);
			return true;
		} catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
			throw new BadCredentialsException("INVALID_CREDENTIALS", ex);
		} catch (ExpiredJwtException ex) {
			throw ex;
		}
	}

	public String getUsernameFromAccessToken(String token) {
		return getUsernameFromToken(token, salt);

	}
	
	public String getUsernameFromRefreshToken(String token) {
		return getUsernameFromToken(token, saltRefresh);

	}
	
	public String getUsernameFromToken(String token, String salt) {
		Claims claims = Jwts.parser().setSigningKey(salt).parseClaimsJws(token).getBody();
		return claims.getSubject();
	}

	public List<SimpleGrantedAuthority> getRolesFromToken(String token) {
		Claims claims = Jwts.parser().setSigningKey(salt).parseClaimsJws(token).getBody();

		List<SimpleGrantedAuthority> roles = null;

		Boolean isAdmin = claims.get("isAdmin", Boolean.class);
		Boolean isManager = claims.get("isManager", Boolean.class);
		Boolean isUser = claims.get("isUser", Boolean.class);

		if (isAdmin != null && isAdmin) {
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
		}
		
		if (isManager != null && isManager) {
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER"));
		}

		if (isUser != null && isAdmin) {
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
		}
		return roles;

	}

}