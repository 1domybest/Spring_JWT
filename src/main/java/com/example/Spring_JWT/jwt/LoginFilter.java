package com.example.Spring_JWT.jwt;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;


public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public LoginFilter(AuthenticationManager authenticationManager) {
        System.out.println("생성자 진입");
        this.authenticationManager = authenticationManager;

        // 기본 경로를 "/join"으로 변경
        setFilterProcessesUrl("/join");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // /join 으로 들어올시 이곳을 거치고 여기에서 authToken 매니저에 아이디와 비밀번호를 넘겨준다 단 UsernamePasswordAuthenticationToken 로 감싸서 넘겨야함
        // 순서는 /join -> SecurityConfig 안에 설정에따라 어디서 검증할지 확인후 이동 (http.addFilterAt(new LoginFilter(), UsernamePasswordAuthenticationFilter.class);)
        // -> attemptAuthentication -> AuthenticationManager -> JoinService -> DB

//        // JSON 데이터 파싱 받는 데이터형식이 form이아닌 json이라면
//        ObjectMapper objectMapper = new ObjectMapper();
//        Map<String, String> jsonMap = objectMapper.readValue(request.getInputStream(), Map.class);
//
//        username = jsonMap.get("username");
//        password = jsonMap.get("password");

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("유저이름:" + username + "비밀번호 :" + password);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        return authenticationManager.authenticate(authToken);
    }

    // 검증 성공시 받는 이벤트 콜백
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("Authentication 검증 성공!");
        super.successfulAuthentication(request, response, chain, authResult);
    }

    // 검증 실패시 받는 이벤트 콜백
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        System.out.println("Authentication 검증 실패 ㅠㅠ");
        super.unsuccessfulAuthentication(request, response, failed);
    }
}
