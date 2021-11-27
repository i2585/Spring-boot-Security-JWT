package com.example.jwt.config.jwt;

import java.io.IOException;
import java.io.PrintWriter;
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
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.dto.JwtDto;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작함

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	
	private final AuthenticationManager authenticationManager;
	
	// /login요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		// 1. username, password 받아서
		// 2. 정상인지 로그인 시도를 해본다. authenticationManager로 로그인 시도 하면
		// PrincipalDetailsService가 호출 loadUserByUsername() 함수 실행
		// 3.PrincipalDetails를 세션에 담고 (권한 관리를 위해서)
		// 4. JWT 토큰을 만들어서 응답해주면 됨 
		
		try {
				//json parsing
				ObjectMapper om = new ObjectMapper();
				User user = om.readValue(request.getInputStream(),User.class);
				System.out.println(user);
				
				UsernamePasswordAuthenticationToken authenticationToken=
						new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
				
				// PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨
				// DB에 있는 username과 password가 일치한다.
				Authentication authentication = 
						authenticationManager.authenticate(authenticationToken);
				
				PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
				System.out.println("로그인 완료됨: " + principalDetails.getUser().getUsername()); // 출력되면 로그인 정상적으로 완료
				
				// authentication 객체가 session영역에 저장하고 return
				// return 이유는 권한 관리를 security가 대신 해주기 때문에 편함
				// JWT 토큰은 세션을 만들 이유가 없지만 단지 권한 처리때문에 session에 넣어 준다.
				return authentication;
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	} 
	
	// attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
	// 해당 함수에서 JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면 됨
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

		// Hash암호방식
		String jwtToken = JWT.create()
				.withSubject(principalDetails.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));
	
		// json으로 response
		PrintWriter out = response.getWriter();
		JwtDto jwt = new JwtDto();
		ObjectMapper objectMapper= new ObjectMapper();
		response.setContentType("application/json");
		response.setCharacterEncoding("utf-8");
		jwt.setAuthorization(JwtProperties.TOKEN_PREFIX + jwtToken);
		String jsonString = objectMapper.writeValueAsString(jwt);
		out.print(jsonString);
		out.flush();
		
//		// header에 JwtToken 실어서 response
//		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
	}
} 




