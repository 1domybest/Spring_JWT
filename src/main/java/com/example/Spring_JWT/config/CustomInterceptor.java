package com.example.Spring_JWT.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

/**
 * API 요청에대한 인터셉터
 */
@Component
public class CustomInterceptor implements HandlerInterceptor {

    /**
     * 컨트롤러 실행 전 호출됨
     * @param request 요청
     * @param response 반환
     * @param handler 핸들러
     * @return boolean = FALSE 리턴시 컨트롤러까지 진입하지 않음
     * @throws Exception 예외
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        System.out.println("PreHandle: 요청 URI - " + "[" + request.getRequestURI() + "]");
        return true;
    }

    /**
     * 컨트롤러 실행 후, 뷰 렌더링 전 호출
     * @param request 요청
     * @param response 반환
     * @param handler 핸들러
     * @param ex 예외상황 발생
     * @throws Exception 예외
     */
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        System.out.println("PostHandle: 요청 완료 후 처리" + request.getRequestURI());
        if (ex != null) {
            System.err.println("예외 발생 -  " + "[" + request.getRequestURI() + "]" + "\n" + "Message = " + ex.getMessage() );
        }
    }

    /***
     * 모든 요청 처리 완료 후 호출됨
     * @param request 요청
     * @param response 반환
     * @param handler 핸들러
     * @param modelAndView 서버사이드 클라이언트일시 반환하는 뷰에대한 정보
     * @throws Exception 예외
     */
    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, @Nullable ModelAndView modelAndView) throws Exception {
        System.out.println("AfterCompletion: 요청 처리 종료 - "  + "[" + request.getRequestURI() + "]");

    }
}

