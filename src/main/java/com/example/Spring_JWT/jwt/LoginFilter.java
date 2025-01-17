package com.example.Spring_JWT.jwt;


import com.example.Spring_JWT.dto.CustomUserDetails;
import com.example.Spring_JWT.entity.RefreshEntity;
import com.example.Spring_JWT.repository.RefreshRepository;
import com.example.Spring_JWT.util.JwtConstants;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.*;


public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshRepository refreshRepository) {
        System.out.println("JWT log: " + "LoginFilter");
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;

        // 기본 경로를 "/login"으로 변경
        setFilterProcessesUrl("/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JWT log: " + "LoginFilter attemptAuthentication");
        // /join 으로 들어올시 이곳을 거치고 여기에서 authToken 매니저에 아이디와 비밀번호를 넘겨준다 단 UsernamePasswordAuthenticationToken 로 감싸서 넘겨야함
        // 순서는 /join -> SecurityConfig 안에 설정에따라 어디서 검증할지 확인후 이동 (http.addFilterAt(new LoginFilter(), UsernamePasswordAuthenticationFilter.class);)
        // -> attemptAuthentication -> AuthenticationManager -> JoinService -> DB

        // JSON 데이터 파싱 받는 데이터형식이 form 이아닌 json 이라면
        ObjectMapper objectMapper = new ObjectMapper();
        Map jsonMap = null;
        try {
            jsonMap = objectMapper.readValue(request.getInputStream(), Map.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String username = jsonMap.get("username").toString();
        String password = jsonMap.get("password").toString();

        System.out.println("유저이름:" + username + "비밀번호 :" + password);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        return authenticationManager.authenticate(authToken);
    }

    // 검증 성공시 받는 이벤트 콜백
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("JWT log: " + "LoginFilter successfulAuthentication");

        CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();
        String username = customUserDetails.getUsername();
        Long memberId = customUserDetails.getMemberId();
        System.out.println("유저의 아이디 " + memberId);
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        String access = jwtUtil.createJwt("access", username, role, JwtConstants.ACCESS_EXPIRED_MS);
        String refresh = jwtUtil.createJwt("refresh", username, role, JwtConstants.REFRESH_EXPIRED_MS);

        //새로운 refresh 생성
        jwtUtil.addRefreshEntity(username, refresh, JwtConstants.REFRESH_EXPIRED_MS);

        // 쿠키에 새로발급한 리프레쉬 토큰 저장
        jwtUtil.addCookieRefreshToken(refresh, response, JwtConstants.REFRESH_EXPIRED_MS);

        // 헤더에 새로발급한 엑세스 토큰 저장
        jwtUtil.addHeaderAccessToken(access, response);

        response.setStatus(HttpStatus.OK.value());

//        // 테스트를 위한 쿠키 클리어
//        jwtUtil.clearAllCookies(request, response);
    }

    // 검증 실패시 받는 이벤트 콜백
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        System.out.println("JWT log: " + "LoginFilter unsuccessfulAuthentication");
        response.setStatus(401); // 토큰 검증실패 status code 401
    }
}
