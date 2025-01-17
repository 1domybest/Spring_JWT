package com.example.Spring_JWT.jwt;

import com.example.Spring_JWT.entity.AuthEntity;
import com.example.Spring_JWT.repository.AuthRepository;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;


/**
 * @see JWTUtil 토큰을 발급 or 재발급 or 토큰을 사용한 정보 추출을 위한 유틸 객체
 */
@Component
public class JWTUtil {
    /**
     * 각 회사에서 사용하는 보안키로
     * application.yml 내 spring.jwt.secret 에 저장되어있다.
     */
    private final SecretKey secretKey;
    private final AuthRepository authRepository;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret, AuthRepository authRepository) {
        System.out.println("JWT log: " + "JWTUtil");
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
        this.authRepository = authRepository;
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

    /**
     * 리프레쉬 토큰을 넣을 Cookie [path를 여러군데에 설정하고싶다면 Cookie 를 그만큼 생성해야환다.]
     * @param key 쿠키 키 [refresh or access]
     * @param value 쿠키 값
     * @param expiredMs 유효시간 밀리세컨즈
     * @return
     */
    public Cookie createCookie(String key, String value, Long expiredMs) {
        int maxAgeInSeconds = (int) (expiredMs / 1000);
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(maxAgeInSeconds);
        //cookie.setSecure(true); // Https(인증서) 일시 이걸 true로
        //cookie.setPath("/"); // 쿠키를 허용한 Path
        cookie.setHttpOnly(true);

        return cookie;
    }

    /**
     * accessToken 을 Header 에 넣는 공통 함수
     * @param accessToken 엑세스 토큰
     * @param response 토큰을 담을 response
     */
    public void addHeaderAccessToken(String accessToken, HttpServletResponse response) {
        response.addHeader("Authorization", "Bearer " + accessToken);
    }

    /**
     * refresh token 을 쿠키에 저장하기위한 공통 함수
     * @param refreshToken 재발급을 위한 리프레시 토큰
     * @param response 쿠키를 담을 response
     * @param expiredMs 쿠키 유효기간
     */
    public void addCookieRefreshToken(String refreshToken, HttpServletResponse response, Long expiredMs) {
        Cookie cookie = createCookie("refresh", refreshToken, expiredMs);
        response.addCookie(cookie);
    }

    /**
     * refresh token 을 서버 DB에 저장하기위한 함수
     * 기본적으로 refresh token 을 사용하여 access token 재발급할시
     * DB의 저장되어있는 refresh token 을 삭제하고 새로 저장하여 복제를 방지
     * @param username 사용자 이름
     * @param refresh 리프레시 토큰
     * @param expiredMs 리프레시 토큰 유효기간
     */
    public void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        AuthEntity authEntity = new AuthEntity();
        authEntity.setUsername(username);
        authEntity.setRefreshToken(refresh);
        authEntity.setExpiration(date.toString());

        authRepository.save(authEntity);
    }


    // ========================
    /**
     * 특정 Key 를 가진 쿠키 삭제
     * @param response 삭제할 response
     * @param key 쿠키의 key
     */
    public void deleteCookie(HttpServletResponse response, String key) {
        Cookie cookie = new Cookie(key, null); // 값은 null로 설정
        cookie.setPath("/"); // 원래 쿠키의 Path와 동일하게 설정해야 함
        cookie.setMaxAge(0); // 0으로 설정하여 즉시 만료
        cookie.setHttpOnly(true); // 기존 쿠키의 설정과 일치시켜야 함
        response.addCookie(cookie); // 응답에 삭제용 쿠키 추가
    }


    /**
     * 쿠키 전체 삭제
     * @param request 요청
     * @param response 반환
     */
    public void clearAllCookies(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                deleteCookie(response, cookie.getName());;
            }
        }
    }
}
