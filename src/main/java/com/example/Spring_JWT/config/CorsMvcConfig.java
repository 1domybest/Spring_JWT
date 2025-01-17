package com.example.Spring_JWT.config;


import com.example.Spring_JWT.util.CommonConstants;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * cors 에러를 방지하기위한 클래스
 */
@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {
        System.out.println("JWT log: " + "CorsMvcConfig addCorsMappings");
        corsRegistry.addMapping("/**")
                .allowedOrigins(CommonConstants.WEB_CLIENT_URL);
    }
}
