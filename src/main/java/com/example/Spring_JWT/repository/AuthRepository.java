package com.example.Spring_JWT.repository;

import com.example.Spring_JWT.entity.AuthEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface AuthRepository extends JpaRepository<AuthEntity,Long> {
    Boolean existsByRefreshToken(String refresh);

    @Transactional
    void deleteByRefreshToken(String refresh);
}
