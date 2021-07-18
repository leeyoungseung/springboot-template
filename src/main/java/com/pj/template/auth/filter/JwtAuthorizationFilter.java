package com.pj.template.auth.filter;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import com.pj.template.auth.model.User;
import com.pj.template.auth.repository.UserRepository;
import com.pj.template.auth.service.PrincipalDetail;
import com.pj.template.auth.util.JwtUtil;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;


public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
	
	private JwtUtil jwtUtil;
	
	private UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, 
			UserRepository userRepository, JwtUtil jwtUtil) {
		super(authenticationManager);
		this.userRepository = userRepository;
		this.jwtUtil = jwtUtil;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		System.out.println("인증이나 권한이 필요한 주소 요청이 됨. JwtAuthorizationFilter doFilterInternal");
		String jwtToken = "";
		try {
			jwtToken = extractJwtFromRequest(request);
			System.out.println("jwtHeader : "+jwtToken);
			System.out.println(jwtUtil.getUsernameFromAccessToken(jwtToken));

			if (StringUtils.hasText(jwtToken) && jwtUtil.validateToken(jwtToken)) {
				Optional<User> data = userRepository.findByUsername(jwtUtil.getUsernameFromAccessToken(jwtToken));
				PrincipalDetail principalDetail = new PrincipalDetail(data.get());

				Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetail, null,
						principalDetail.getAuthorities());

				SecurityContextHolder.getContext().setAuthentication(authentication);
			} else {
				System.out.println("Cannot set the Security Context");
			}
			chain.doFilter(request, response);
			
		} catch (ExpiredJwtException e) {
			executeRefreshTokenCheckPro(request, response);

		} catch (BadCredentialsException e) {
			request.setAttribute("exception", e);
		} 
		
	}
	
	
	private void executeRefreshTokenCheckPro(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("executeRefreshTokenCheckPro Start");
		// # access token 검증에 실패하면 refresh token의 검증을 실시한다.
		
		// (1) refresh token이 있는지확인
		try {
			//String jwtToken = extractJwtFromRequest(request);
			String refreshToken = request.getHeader("Refresh-Token");
			
			// (2) refresh token이 유효하다면, access token을 갱신한다.
			if (StringUtils.hasText(refreshToken) && jwtUtil.validateRefreshToken(refreshToken)) {
				Optional<User> data = userRepository.findByRefreshToken(refreshToken);
				PrincipalDetail principalDetail = new PrincipalDetail(data.get());
				
			// (3) access token재발급 
				updateAccessToken(request, response, principalDetail);
				
			} else {
				System.out.println("Refresh Cannot set the Security Context");
			}
			
		} catch (ExpiredJwtException e) {
			System.out.println("RefreshToken ExpiredJwtException Start");

		} catch (BadCredentialsException e) {
			request.setAttribute("exception-refresh", e);
		} 

	}
	

	private void updateAccessToken(HttpServletRequest request, HttpServletResponse response,
			PrincipalDetail principalDetail) throws IOException {
		String accessToken = jwtUtil.generateToken(principalDetail);

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("Authorization", "Bearer "+accessToken);
		jsonObject.put("Status", "0000");
		jsonObject.put("Result", "Success");
		
		response.setContentType("application/json;charset=UTF-8");
		response.getWriter().write(jsonObject.toString());
		response.getWriter().flush();

	}

	private String extractJwtFromRequest(HttpServletRequest request) {
		String bearerToken = request.getHeader("Authorization");
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7, bearerToken.length());
		}
		return null;
	}

}
