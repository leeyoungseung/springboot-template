package com.pj.template.auth.filter;


import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.simple.JSONObject;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pj.template.auth.model.User;
import com.pj.template.auth.repository.UserRepository;
import com.pj.template.auth.service.PrincipalDetail;
import com.pj.template.auth.util.JwtUtil;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	private UserRepository userRepository;
    private JwtUtil jwtUtil;
    
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, UserRepository userRepository, JwtUtil jwtUtil) {
    	this.authenticationManager = authenticationManager;
    	this.userRepository = userRepository;
    	this.jwtUtil = jwtUtil;
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		try {

			
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println("attemptAuthentication param "+ user);
			// (1) 파라미터 유효성체크
			
			
			// (2) 유저가 있는지 확인
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);
			System.out.println("attemptAuthentication 3");
			// authentication 객체가 session영역에 저장됨 => 로그인이 되었다는 뜻임 
			PrincipalDetail principalDetails = (PrincipalDetail) authentication.getPrincipal();	
			
			return authentication;
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}
	
	// attemptAuthentication 실행후 인증이 정상적을 되었으면 이 메서드가 실행됨
	// JWT 토큰을 만들어서 reqeust요청한 사용자에게 토큰을 response해준다.
	@SuppressWarnings("unchecked")
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication : 인증 완료");
		PrincipalDetail principalDetail = (PrincipalDetail) authResult.getPrincipal();
		System.out.println("principalDetail : "+principalDetail.getUser());
		
		// (1) Access-Token, Refresh-Token발급
		String accessToken = jwtUtil.generateToken(principalDetail);
		String refreshToken = jwtUtil.generateRefreshToken(principalDetail);
		
		// (2) Refresh-Token을 DB에 저장하기
		Optional<User> userOptional = userRepository.findByUsername(principalDetail.getUser().getUsername());
		User user = userOptional.get();
		user.setRefreshToken(refreshToken);
		userRepository.save(user);
		
		// (3) 로그인 결과 (토큰셋) 리턴
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("Authorization", "Bearer "+accessToken);
		jsonObject.put("Refresh-Token", refreshToken);
		jsonObject.put("Status", "0000");
		jsonObject.put("Result", "Success");
		
		response.setContentType("application/json;charset=UTF-8");
		response.getWriter().write(jsonObject.toString());
		response.getWriter().flush();
		
	}
	
	
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		System.out.println("successfulAuthentication : 인증 실패");
		System.out.println(failed.getClass());
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("Result", "Failure");
		
		if (failed instanceof InternalAuthenticationServiceException) {
			System.out.println(failed);
			jsonObject.put("Status", "a401");
			jsonObject.put("Message", "Not exist User.");
			
		} else if (failed instanceof BadCredentialsException){
			System.out.println(failed);
			jsonObject.put("Status", "a402");
			jsonObject.put("Message", "Not match password.");
			
		} else {
			System.out.println(failed);
			jsonObject.put("Status", "a403");
			jsonObject.put("Message", "Server Error.");
			
		}
		
		response.setContentType("application/json;charset=UTF-8");
		response.getWriter().write(jsonObject.toString());
		response.getWriter().flush();

	}

}
