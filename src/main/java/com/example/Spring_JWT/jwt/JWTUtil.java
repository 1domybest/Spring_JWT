package com.example.Spring_JWT.jwt;

import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

// 이부분은 토큰을 생성하거나 수정 등 tool 클래스
@Component
public class JWTUtil {
    private final SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        System.out.println("JWT log: " + "JWTUtil");
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    /**
     * 토큰에서 유저이름 추출
     * 1. 시크릿코드로 우리가 발급한 토큰인지 확인
     * 2. JWT 토큰에서 유저 이름 추출
     * @param token JWT 토큰
     * @return String username
     */
    public String getUsername(String token) {
        return Jwts
                .parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("username", String.class);
    }


    /**
     * 토큰에서 역할추출
     * 1. 시크릿코드로 우리가 발급한 토큰인지 확인
     * 2. JWT 토큰에서 유저 권한(역할) 추출
     * @param token
     * @return String role
     */
    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    /**
     * 토큰 유효기간 검증
     * 1. 시크릿코드로 우리가 발급한 토큰인지 확인
     * 2. JWT 토큰에서 현재 시간과 토큰의 유효기간 추출후 검증
     * @param token JWT 토큰
     * @return Boolean True = 유효, False = 만료
     */
    public Boolean isExpired(String token) {
        System.out.println("현재 시간 " + new Date(System.currentTimeMillis()));
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }
//현재 시간 Thu Jan 16 16:50:08 KST 2025
    /**
     * 토큰 발급
     * @param username 유저이름
     * @param role 역할
     * @param expiredMs 유효기간
     * @return String JWT 토큰
     */
    public String createJwt(String category, String username, String role, Long expiredMs) {
        System.out.println("등록한 시간 " + new Date(System.currentTimeMillis() + expiredMs));
        return Jwts.builder()
                .claim("category", category)
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }


    /**
     * 토큰의 종류 확인코드
     * @param token 토큰
     * @return String [access, refresh]
     */
    public String getCategory(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }


}
