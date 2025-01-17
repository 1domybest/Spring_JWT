package com.example.Spring_JWT.jwt;


import com.example.Spring_JWT.dto.CustomUserDetails;
import com.example.Spring_JWT.repository.AuthRepository;
import com.example.Spring_JWT.util.JwtConstants;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.*;


/**
 * @see com.example.Spring_JWT.config.SecurityConfig 에서 사용하는 로그인 요청 필터
 */
public class CustomLoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    public CustomLoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, AuthRepository authRepository) {
        System.out.println("JWT log: " + "LoginFilter");
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;

        // 기본 경로를 "/login"으로 변경
        setFilterProcessesUrl("/login");
    }

    /**
     * @see com.example.Spring_JWT.config.SecurityConfig 에서 
     * 등록된 필터의 순서에따라 순차적으로 실행되고 차례가 되었을때 가장먼저 실행되는 부분
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JWT log: " + "LoginFilter attemptAuthentication");

        // JSON 데이터 파싱 받는 데이터형식이 form 이아닌 json 이라면
        ObjectMapper objectMapper = new ObjectMapper();
        Map jsonMap = null;
        try {
            jsonMap = objectMapper.readValue(request.getInputStream(), Map.class);
        } catch (IOException e) {
            // 데이터가 없음으로 예외처리
            throw new RuntimeException(e);
        }
        String username = jsonMap.get("username").toString();
        String password = jsonMap.get("password").toString();

        System.out.println("유저이름:" + username + "비밀번호 :" + password);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        return authenticationManager.authenticate(authToken);
    }

    /**
     * 토큰 검증이 성공하였을때 호출되는 함수
     * @param request http 요청
     * @param response http 반환
     * @param chain 필터체인 = 다음필터로 넘기기위해 사용
     * @param authResult 검증 결과
     * @throws IOException IO 예외
     * @throws ServletException 통신 예외
     */
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

        String access = jwtUtil.createJwt(JwtConstants.ACCESS, username, role, JwtConstants.ACCESS_EXPIRED_MS);
        String refresh = jwtUtil.createJwt(JwtConstants.REFRESH, username, role, JwtConstants.REFRESH_EXPIRED_MS);

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

    /**
     *
     * @param request http 요청
     * @param response http 반환
     * @param failed 검증 실패시 예외
     * @throws IOException IO 예외
     * @throws ServletException 통신 예외
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        System.out.println("JWT log: " + "LoginFilter unsuccessfulAuthentication");
        response.setStatus(401); // 토큰 검증실패 status code 401
    }
}
