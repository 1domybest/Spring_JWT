package com.example.Spring_JWT.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

/**
 * 회원 Entity
 */
@Entity
@Getter @Setter
public class UserEntity {

    /**
     * PK
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 유저 이름
     */
    private String username;

    /**
     * 비밀번호
     */
    private String password;

    /**
     * 역할 권한
     */
    private String role;
}
