package com.example.Spring_JWT.jwt;


import com.example.Spring_JWT.repository.AuthRepository;
import com.example.Spring_JWT.util.CommonConstants;
import com.example.Spring_JWT.util.JwtConstants;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import java.io.IOException;

/**
 * @see com.example.Spring_JWT.config.SecurityConfig 에서 사용하는 로그아웃 요청 필터
 */
@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilter {

    private final JWTUtil jwtUtil;
    private final AuthRepository authRepository;

    /**
     * 기본적으로 스프링 시큐리티에서
     * @see LogoutFilter 를 제공해줌으로써
     * 제공된 필터를 등록하고 logout 요청시 아래 doFilter 가 실행됨
     * 이후 내가 커스텀한 비지니스 로직(customDoFilter) 을 실행하면 됨
     * @param servletRequest http 요청
     * @param servletResponse http 반환
     * @param filterChain 다음필터로 넘기기위해 사용
     * @throws IOException IO 예외
     * @throws ServletException 통신 예외
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("LogoutFilter " + "doFilter" );
        customDoFilter((HttpServletRequest)servletRequest, (HttpServletResponse) servletResponse, filterChain);
    }

    /**
     * 위 doFilter 에서 다이렉트로 실행하는
     * 커스텀 비지니스로직 필터 함수
     * @param request http 요청
     * @param response http 반환
     * @param filterChain 다음필터로 넘기기위해 사용
     * @throws IOException IO 예외
     * @throws ServletException 통신 예외
     */
    private void customDoFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        //path and method verify
        String requestUri = request.getRequestURI();
        if (!requestUri.matches("^\\/logout$")) {

            filterChain.doFilter(request, response);
            return;
        }
        String requestMethod = request.getMethod();
        if (!requestMethod.equals(CommonConstants.POST)) {

            filterChain.doFilter(request, response);
            return;
        }

        //get refresh token
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            if (cookie.getName().equals(JwtConstants.REFRESH)) {

                refresh = cookie.getValue();
            }
        }

        //refresh null check
        if (refresh == null) {

            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //expired check
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {

            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);
        if (!category.equals(JwtConstants.REFRESH)) {

            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //DB에 저장되어 있는지 확인
        Boolean isExist = authRepository.existsByRefreshToken(refresh);
        if (!isExist) {

            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //로그아웃 진행
        //Refresh 토큰 DB에서 제거
        authRepository.deleteByRefreshToken(refresh);

        jwtUtil.deleteCookie(response, JwtConstants.REFRESH);

        response.setStatus(HttpServletResponse.SC_OK);
    }
}
