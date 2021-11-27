package com.example.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;  

@Configuration
public class CorsConfig {
	
	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true); // �������� ������ �� �� json�� �ڹٽ�ũ��Ʈ���� ó���� �� �ְ� ������ �����ϴ� ��
		config.addAllowedOrigin("*"); // ��� ip�� ������ ����ϰڴ�.
		config.addAllowedHeader("*"); // ��� header�� ������ ����ϰڴ�.
		config.addAllowedMethod("*"); // ��� post, get, put, delete, patch ��û�� ����ϰڴ�.
		source.registerCorsConfiguration("/api/**", config);
		return new CorsFilter(source);
	}
}