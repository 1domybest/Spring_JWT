package com.example.Spring_JWT.util;
import com.example.Spring_JWT.handler.ErrorHandler;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collection;

/**
 * SecurityContextUtil
 * SecurityContext 를 사용하여 사용자의 정보를 얻는 싱글톤 형식의 class
 */
@RequiredArgsConstructor
public class SecurityContextUtil {

    /**
     * Authentication 에서 유저 이름 추출
     * @return String username
     */
    public static String getUsername() {

        Authentication authentication = getAuthentication();
        return authentication != null ? authentication.getName() : null;
    }

    /**
     * Authentication 에서 역할 권한 추출
     * @return String role
     */
    public static String getRole() {
        Authentication authentication = getAuthentication();
        if (authentication == null) {
            return null;
        }

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst()
                .orElse(null);
    }

    /**
     * Authentication 에서 유저이름, 역할권한 추출
     * @return DTO 가 올예정
     */
    public static String getUserInfoBySecurityContext(HttpServletResponse response) {
        String username = getUsername();
        String role = getRole();
        if (username == null || role == null) {
            ErrorHandler.notFoundMember(response);
        }
        // 여기에서 DTO 반환
        return role + username;
    }

    /**
     * SecurityContext 로부터 Authentication 추출
     * @return Authentication 회원 정보가 담겨있는 객체
     */
    private static Authentication getAuthentication() {
        SecurityContext context = SecurityContextHolder.getContext();
        return context != null ? context.getAuthentication() : null;
    }

}

