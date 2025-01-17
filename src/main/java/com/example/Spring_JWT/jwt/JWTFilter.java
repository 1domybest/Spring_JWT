package com.example.Spring_JWT.jwt;

import com.example.Spring_JWT.dto.CustomUserDetails;
import com.example.Spring_JWT.entity.UserEntity;
import io.jsonwebtoken.ExpiredJwtException;
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
import java.io.PrintWriter;
import java.util.Objects;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("JWT log: " + "JWTFilter doFilterInternal");
        // 헤더에서 access키에 담긴 토큰을 꺼냄
        String accessToken = request.getHeader("access");

        // 토큰이 없다면 다음 필터로 넘김
        if (accessToken == null) {
            // doFilter 는 SecurityConfig filterChain 에 등록된 필터중 현재 진행중인 필터를 pass하고 다음 필터로 넘어가는 의미이다.
            // 단 문제가있을시에는 return을 하는게맞다.
            // accessToken 이 없다는건 login 전 상태 요청일수도 있으니까 다음 필터로 넘기고 로그인을 진행해면 된다.
            // 아마 이다음 필터는 LoginFilter 임
            filterChain.doFilter(request, response);
            System.out.println("토큰이 없음");
            return;
        } else {
            System.out.println("토큰이 있음");
        }

        // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
        try {
            jwtUtil.isExpired(accessToken);
        } catch (ExpiredJwtException e) {

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            // 만료시에는 DoFilter가 아닌 그냥 return
            return;
        }

        // 토큰이 access인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken);

        if (!category.equals("access")) {

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            //response status code
            // 들어온 토큰이 refresh토큰 혹은 access토큰이 아니라면 에러 반환후 클라에서 토큰 재발급 요청
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        System.out.println("access token 괜찮");

        // username, role 값을 획득
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);
        // 로그인이 성공했을시에 SecurityContextHolder 에 등록되면 특정시간동안 세션을 유지할수있다.
        filterChain.doFilter(request, response);

    }
}
