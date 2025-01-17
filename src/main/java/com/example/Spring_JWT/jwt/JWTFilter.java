package com.example.Spring_JWT.jwt;

import com.example.Spring_JWT.dto.CustomUserDetails;
import com.example.Spring_JWT.entity.UserEntity;
import com.example.Spring_JWT.util.CommonConstants;
import com.example.Spring_JWT.util.JwtConstants;
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

/**
 * 토큰 검증 클래스
 * @see com.example.Spring_JWT.config.SecurityConfig 에서 사용하는 JWT 토큰 검증 요청 필터
 */
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    /**
     * 토큰을 발급 or 재발급 or 토큰을 사용한 정보 추출을 위한 유틸 객체
     */
    private final JWTUtil jwtUtil;

    /**
     * @see com.example.Spring_JWT.config.SecurityConfig 에서
     * 등록된 필터의 순서에따라 순차적으로 실행되고 차례가 되었을때 가장먼저 실행되는 부분
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("JWT log: " + "JWTFilter doFilterInternal");
        // 헤더에서 access token 에 담긴 토큰을 꺼냄
        String accessToken = request.getHeader(JwtConstants.ACCESS);

        // 토큰이 없다면 다음 필터로 넘김
        if (accessToken == null) {
            // doFilter 는 SecurityConfig filterChain 에 등록된 필터중 현재 진행중인 필터를 pass 하고 다음 필터로 넘어가는 의미이다.
            // 단 문제가있을시에는 return 을 하는게맞다.
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
            // 만료시에는 doFilter 가 아닌 그냥 return
            return;
        }

        // 토큰이 access 인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken);

        if (!category.equals(JwtConstants.ACCESS)) {

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            //response status code
            // 들어온 토큰이 refresh 토큰 혹은 access 토큰이 아니라면 에러 반환후 클라에서 토큰 재발급 요청
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }


        // username, role 값을 획득
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // 로그인이 성공했을시에 SecurityContextHolder 에 등록되면 세선이 돌아가면서 다른 클래스에서도 사용자의 정보를 가져올수있음
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);

    }
}
