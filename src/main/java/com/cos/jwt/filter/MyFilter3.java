package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		// 토큰 : jjh 만들어줘야함 id,pw가 정상적으로 들어와 로그인이 완료되면 토큰을 만들어줌
		// 요청할 때 마다 header에 Authorization에 value값으로 토큰을 가지고옴
		// 토큰이 넘어오면 서버가 만든 토큰이 맞는지 검증만 하면 됨
		if (req.getMethod().equals("POST")) {
			System.out.println("포스트");
			String headerAuth = req.getHeader("Authorization");
			System.out.println(headerAuth);
			System.out.println("필터3");
			if (headerAuth.equals("jjh")) {
				chain.doFilter(req, res);
			}else {
				PrintWriter out = res.getWriter();
				out.println("인증안됨");
			}
		}
		
		
	}
	
	

}
