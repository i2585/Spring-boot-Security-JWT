package com.example.jwt.config.jwt;

public interface JwtProperties {
	String SECRET = "cos"; // �츮 ������ �˰� �ִ� ��а�
	int EXPIRATION_TIME = 60000*10; // (1/1000��)
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}
