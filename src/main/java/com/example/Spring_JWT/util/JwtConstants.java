package com.example.Spring_JWT.util;

/**
 * 토큰 유효시간 전역변수
 */
public class JwtConstants {
    public static final String ACCESS = "access";
    public static final String REFRESH = "refresh";

    // 1분을 밀리초로 변환
    public static final long MIN_MS = 60 * 1000L; // 1분 = 60,000ms
    // 1시간을 밀리초로 변환
    public static final long HOUR_MS = MIN_MS * 60 * 1000L; // (1분 * 60) = 1시간
    // 엑세스 토큰 만료 시간 (10분)
    public static final long ACCESS_EXPIRED_MS = MIN_MS * 10; // 1분 * 10 = 10분
    // 리프레시 토큰 만료 시간 (24시간)
    public static final long REFRESH_EXPIRED_MS = HOUR_MS * 24; // (1시간) * 24 = 24시간
}
