package com.example.Spring_JWT.jwt;

import com.example.Spring_JWT.dto.CustomUserDetails;
import com.example.Spring_JWT.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // request에서 Authorization 추출
        String authorization = request.getHeader("Authorization");

        // Authorization 헤더검증
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("token is null");
            filterChain.doFilter(request, response);

            // 토큰이 없으면 함수종료
            return;
        }

        // Bearer 부분 제거 후 순수 토큰만 획득
        String token = authorization.split(" ")[1];

        //  리프레쉬 토큰이라면 return [refresh 는 오로지 재발급을 위한 토큰이기 때문에]
        if (Objects.equals(jwtUtil.getCategory(token), "refresh")) {
            System.out.println("token is refresh token");
            filterChain.doFilter(request, response);
            return;
        }

        //토큰 만료 시간 검증
        if (jwtUtil.isExpired(token)) {
            System.out.println("token is expired");
            filterChain.doFilter(request, response);

            // 토큰 만료시에 함수종료
            return;
        }

        // 토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        //userEntity를 생성하여 값 set
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("1234");
        userEntity.setRole(role);

        //UserDetails 에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);

    }
}
