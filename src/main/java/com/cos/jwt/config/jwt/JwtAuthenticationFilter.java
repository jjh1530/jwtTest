package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 이 필터를 이용하여 username, password를 받아 로그인처리함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	private final AuthenticationManager authenticationManager;
	
	//login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

			System.out.println("JwtAuthentication 로그인 시도중");
		
			//1.username, password 받기
			try {
				ObjectMapper om = new ObjectMapper();
				User user = om.readValue(request.getInputStream(), User.class);
				System.out.println(user);
				
				//토큰 생성
				UsernamePasswordAuthenticationToken authenticationToken =
						new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
				//PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication 리턴
				Authentication authentication =
						authenticationManager.authenticate(authenticationToken);
				
				PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
				System.out.println(principalDetails.getUser().getUsername()+"로그인 완료");

				
				//jwt를 사용하하면서 session을 사용하지 않지만 권환 관리를 위해 return하여 session생성
				return authentication;
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			//2.정상 로그인 시도
			//authenticationManager로 로그인 시도를하면 
			//PrincipalDetailsService가 실행되며 loadUserByName이 실행된다.
			
			//3.PrincipalDetails를 세션에 담는다(권한)
		return null;
	}
	
	// attemptAuthentication실행 후 인증이 정상적일 대 함수 실행
	//JWT 토근 만들어 사용자에게 JWT 토큰 response
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행 인증완료");
		
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
		
		String jwtToken = JWT.create()
				.withSubject(principalDetails.getUsername()) // 토큰이름
				.withExpiresAt(new Date(System.currentTimeMillis()+(60000*10))) //만료시간(현재시간 + 10분)
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("jjh"));  //시크릿값
		System.out.println(jwtToken+"jwtToken");
		
		response.addHeader("Authorization", "Bearer "+jwtToken);
	}
}
