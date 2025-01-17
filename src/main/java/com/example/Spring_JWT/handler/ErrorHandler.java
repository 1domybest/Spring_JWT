package com.example.Spring_JWT.handler;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;


/**
 * 에러 핸들러
 * (싱글톤)
 */
public class ErrorHandler {

    /**
     * 싱글톤을 위한 빈 생성자
     */
    private ErrorHandler() {
        // Private constructor to prevent instantiation
    }

    /**
     * SecurityContextHolder.getContext 에저장되어있는 검증정보를 가지고
     * 회원정보를 조회했을시 찾지 못했을때의 예외처리
     * @param response 상태코드를 반환할 response
     */
    public static void notFoundMember(HttpServletResponse response) {
        response.setStatus(HttpStatus.NOT_FOUND.value());
    }

}
