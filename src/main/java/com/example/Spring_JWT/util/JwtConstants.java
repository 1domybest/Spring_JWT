package com.example.Spring_JWT.util;

public class JwtConstants {
    // 1분을 밀리초로 변환
    public static final long MIN_MS = 60 * 1000L; // 1분 = 60,000ms
    // 1시간을 밀리초로 변환
    public static final long HOUR_MS = 60 * 60 * 1000L; // 1시간 = 3,600,000ms
    // 엑세스 토큰 만료 시간 (10시간)
    public static final long ACCESS_EXPIRED_MS = HOUR_MS * 10; // 10시간 = 36,000,000ms
    // 리프레시 토큰 만료 시간 (24시간)
    public static final long REFRESH_EXPIRED_MS = HOUR_MS * 24; // 24시간 = 86,400,000ms
}
