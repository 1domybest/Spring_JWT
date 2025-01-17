package com.example.Spring_JWT.controller;

import com.example.Spring_JWT.jwt.JWTUtil;
import com.example.Spring_JWT.repository.AuthRepository;
import com.example.Spring_JWT.util.JwtConstants;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final JWTUtil jwtUtil;
    private final AuthRepository authRepository;

    @PostMapping("/token-refresh")
    public ResponseEntity<?> tokenRefresh(HttpServletRequest request, HttpServletResponse response) {
        //get refresh token
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            if (cookie.getName().equals("refresh")) {

                refresh = cookie.getValue();
            }
        }

        if (refresh == null) {

            //response status code
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        //expired check
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {

            //response status code
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        //DB에 저장되어 있는지 확인
        Boolean isExist = authRepository.existsByRefreshToken(refresh);
        if (!isExist) {

            //response body
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);

        if (!category.equals("refresh")) {

            //response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        String newAccess = jwtUtil.createJwt("access", username, role, JwtConstants.ACCESS_EXPIRED_MS);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, JwtConstants.REFRESH_EXPIRED_MS);

        //기존 Refresh 토큰 DB에서 삭제
        authRepository.deleteByRefreshToken(refresh);

        //새로운 refresh 생성
        jwtUtil.addRefreshEntity(username, newRefresh, JwtConstants.REFRESH_EXPIRED_MS);

        // 쿠키에 새로발급한 리프레쉬 토큰 저장
        jwtUtil.addCookieRefreshToken(newRefresh, response, JwtConstants.REFRESH_EXPIRED_MS);

        // 헤더에 새로발급한 엑세스 토큰 저장
        jwtUtil.addHeaderAccessToken(newAccess, response);

        return new ResponseEntity<>(HttpStatus.OK);
    }
}
