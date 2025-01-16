package com.example.Spring_JWT.config;

import com.example.Spring_JWT.jwt.JWTFilter;
import com.example.Spring_JWT.jwt.JWTUtil;
import com.example.Spring_JWT.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // 설정파일이다
@EnableWebSecurity // 시큐리티 파일이다
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


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
        System.out.println("필터진입");
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



        //  before At after 을 사용하는 이유는 이걸 지정하지않고 At을 사용한다면
        // 동작의 순서가 보장되지 않기때문이다.

        // LoginFilter 가 실행되기 전에 JWTFilter를 실행하겠다
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // LoginFilter 를 즉시 실행하겠다
        http
                .addFilterAt(
                        new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil),
                        UsernamePasswordAuthenticationFilter.class
                );


        // JWT 방식에서는 상태를 저장하지않기때문에 상태정책에서 빼겠다
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }
}
