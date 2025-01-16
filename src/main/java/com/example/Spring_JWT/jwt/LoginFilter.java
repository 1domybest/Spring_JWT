package com.example.Spring_JWT.jwt;


import com.example.Spring_JWT.dto.CustomUserDetails;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;


public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        System.out.println("생성자 진입");
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;

        // 기본 경로를 "/login"으로 변경
        setFilterProcessesUrl("/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // /join 으로 들어올시 이곳을 거치고 여기에서 authToken 매니저에 아이디와 비밀번호를 넘겨준다 단 UsernamePasswordAuthenticationToken 로 감싸서 넘겨야함
        // 순서는 /join -> SecurityConfig 안에 설정에따라 어디서 검증할지 확인후 이동 (http.addFilterAt(new LoginFilter(), UsernamePasswordAuthenticationFilter.class);)
        // -> attemptAuthentication -> AuthenticationManager -> JoinService -> DB

        // JSON 데이터 파싱 받는 데이터형식이 form이아닌 json이라면
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, String> jsonMap = null;
        try {
            jsonMap = objectMapper.readValue(request.getInputStream(), Map.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String username = jsonMap.get("username");
        String password = jsonMap.get("password");

//        String username = obtainUsername(request);
//        String password = obtainPassword(request);

        System.out.println("유저이름:" + username + "비밀번호 :" + password);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        return authenticationManager.authenticate(authToken);
    }

    // 검증 성공시 받는 이벤트 콜백
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("Authentication 검증 성공!");
        CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();
        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        Long expiredMs = 60 * 60 * 10L;  // 60초 * 60분 * 10시간 = 10시간

        String token = jwtUtil.createJwt(username, role, expiredMs);

        // Bearer 하고 띄어쓰기를 꼭해야함
        // Authorization: Bearer token
        response.addHeader("Authorization", "Bearer " + token);
    }

    // 검증 실패시 받는 이벤트 콜백
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        System.out.println("Authentication 검증 실패 ㅠㅠ");
        response.setStatus(401); // 토큰 검증실패 status code 401
    }
}
