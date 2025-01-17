package com.example.Spring_JWT.config;

import com.example.Spring_JWT.jwt.CustomLogoutFilter;
import com.example.Spring_JWT.jwt.JWTFilter;
import com.example.Spring_JWT.jwt.JWTUtil;
import com.example.Spring_JWT.jwt.CustomLoginFilter;
import com.example.Spring_JWT.repository.AuthRepository;
import com.example.Spring_JWT.util.CommonConstants;
import jakarta.servlet.http.HttpServletRequest;
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
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

/**
 * 스프링 시큐리티
 */
@Configuration // 설정파일이다
@EnableWebSecurity // 시큐리티 파일이다
@RequiredArgsConstructor
public class SecurityConfig {

    /**
     * 시큐리티 검증설정 객체
     */
    private final AuthenticationConfiguration authenticationConfiguration;

    /**
     * JWT 관련 유틸함수 모음
     */
    private final JWTUtil jwtUtil;

    /**
     * 토큰저장 전용 Entity
     */
    private final AuthRepository authRepository;


    /**
     * @see SecurityFilterChain 의 아래 filterChain 가 실행되고 http.build 된후 호출되는 함수
     * @param authenticationConfiguration 보안 검증설정 객체
     * @return AuthenticationManager 검증객체 매니저
     * @throws Exception 예외
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        System.out.println("JWT log: " + "SecurityConfig authenticationManager");
        return authenticationConfiguration.getAuthenticationManager();
    }


    /**
     * 비밀번호 암호화
     * @return BCryptPasswordEncoder
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        System.out.println("JWT log: " + "SecurityConfig bCryptPasswordEncoder");
        return new BCryptPasswordEncoder();
    }

    /**
     * 시큐리티 필터체인 설정
     * 이곳에서 보안설정을 한다
     * 앱이 실행되고 단 1번 호출됨
     * @return SecurityFilterChain
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        System.out.println("JWT log: " + "SecurityConfig filterChain");

        http.cors((cors) -> cors
                        .configurationSource(new CorsConfigurationSource() {
                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                                CorsConfiguration configuration = new CorsConfiguration();
                                // CORS는 프론트 서버의 포트와 백엔드 서버의 포트가 다르기때문에
                                // 리소스의 교차로인한 충돌에러인데 그렇기때문에 이 백엔드서버가 반환해주는 주소중에
                                // 이런것을 허용할 주소를 저장해두는 작업을 뜻한다.
                                // CorsMvcConfig 에도 만들어서 이 주소를 사용하는것보니 스태틱으로 관리하거나 yml로 관리하는게 좋겠다.
                                configuration.setAllowedOrigins(Collections.singletonList(CommonConstants.WEB_CLIENT_URL));
                                configuration.setAllowedMethods(Collections.singletonList("*"));
                                configuration.setAllowCredentials(true);
                                configuration.setAllowedHeaders(Collections.singletonList("*"));

                                // 프론트쪽에서 이 필터체인에대한 검증결과에대한 유효시간이다.
                                // 이시간안에서는 추가로 cors검사를 하지않는다.
                                configuration.setMaxAge(3600L);

                                // 노출할 헤더 명
                                configuration.setExposedHeaders(Collections.singletonList("Authorization"));
                                return null;
                            }
                        })
                );

        // csrf 비활성화
        http.csrf((auth) -> auth.disable());

        // web 이아니고 restful api 이기때문에
        // form 로그인 방식 비활성화
        http.formLogin((auth) -> auth.disable());

        // web 이아니고 restful api 이기때문에
        // http basic 인증 방식 비활성화
        http.httpBasic((auth) -> auth.disable());

        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/login", "/", "/join").permitAll() // 허용
                .requestMatchers("/admin").hasRole("ADMIN")
                .requestMatchers("/reissue").permitAll()
                // 권한필요 단 토큰이 없는데 여기까지 올일이 없음
                // 단 혹시나 토큰이 없거나 role이 다르다면 바로 다음 필터로 넘어감

                .anyRequest().authenticated() // 나머지는 다 가능 else
        );


        /*
         * before At after 을 사용하는 이유는 이걸 지정하지않고 At을 사용한다면
         * 동작의 순서가 보장되지 않기때문이다.
         */

        // LoginFilter 가 실행되기 전에 JWTFilter를 실행하겠다
        http.addFilterBefore(new JWTFilter(jwtUtil), CustomLoginFilter.class);

        // LoginFilter 를 즉시 실행하겠다
        http.addFilterAt(new CustomLoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, authRepository),
                        UsernamePasswordAuthenticationFilter.class);


        // CustomLogoutFilter 는 LogoutFilter 을 상속받았기때문에 기본적으로 LogoutFilter 가 먼저 실행되고 그안에서
        // 따로 이베트 콜백을 받아서 커스텀한 비지니스 로직이 진행된다.
        http.addFilterBefore(new CustomLogoutFilter(jwtUtil, authRepository), LogoutFilter.class);


        // JWT 방식에서는 상태를 저장하지않기때문에 상태정책에서 빼겠다
        http.sessionManagement((session) -> session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
