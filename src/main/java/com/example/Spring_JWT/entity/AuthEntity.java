package com.example.Spring_JWT.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

/**
 * 토큰관련 Entity
 * refresh token 을 사용하여 access token 를 재발급할떄마다
 * refresh token 도 함꼐 재발급을 위한 Entity
 */
@Entity
@Getter @Setter
public class AuthEntity {

    /**
     * PK
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 유저이름
     */
    private String username;

    /**
     * refresh token
     */
    private String refreshToken;

    /**
     * refresh token 유효기간
     */
    private String expiration;
}
