package com.example.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.example.jwt.config.jwt.JwtAuthenticationFilter;
import com.example.jwt.config.jwt.JwtAuthorizationFilter;
import com.example.jwt.repository.UserRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Autowired
	private CorsConfig corsConfig;
	
	@Autowired
	private UserRepository userRepositroy;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
//		http.addFilterBefore(new MyFilter1(),SecurityContextPersistenceFilter.class);
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and() 
		.addFilter(corsConfig.corsFilter()) //@CrossOrigin(인증X), 시큐리티 필터에 등록 인증(O)
		.formLogin().disable()
		.httpBasic().disable()
		.addFilter(new JwtAuthenticationFilter(authenticationManager()))
		.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepositroy))
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
			.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**")
			.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**")
			.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll();		
	}
}
