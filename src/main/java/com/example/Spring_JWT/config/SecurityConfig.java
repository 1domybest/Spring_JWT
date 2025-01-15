package com.example.Spring_JWT.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // 설정파일이다
@EnableWebSecurity // 시큐리티 파일이다
public class SecurityConfig {

    /**
     * 비밀번호 암호화
     * @return BCryptPasswordEncoder
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 시큐리티 필터체인 설정
     * @return SecurityFilterChain
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // csrf 비활성화
        http

                .csrf((auth) -> auth.disable());

        // web 이아니고 restful api 이기때문에
        // form 로그인 방식 비활성화
        http
                .formLogin((auth) -> auth.disable());

        // web 이아니고 restful api 이기때문에
        // http basic 인증 방식 비활성화
        http
                .httpBasic((auth) -> auth.disable());

        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/login", "/", "/join").permitAll() // 허용
                .requestMatchers("/admin").hasRole("ADMIN") // 권한필요
                .anyRequest().authenticated() // 나머지는 다 가능 else
        );

        // JWT 방식에서는 상태를 저장하지않기때문에 상태정책에서 빼겠다
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }
}
