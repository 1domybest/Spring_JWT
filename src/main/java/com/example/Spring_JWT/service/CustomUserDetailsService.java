package com.example.Spring_JWT.service;

import com.example.Spring_JWT.dto.CustomUserDetails;
import com.example.Spring_JWT.entity.UserEntity;
import com.example.Spring_JWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("JWT log: " + "CustomUserDetailsService loadUserByUsername");
        System.out.println("들어온 유저이름 " + username);
        UserEntity userEntity = this.userRepository.findByUsername(username);
        if (userEntity != null) {
            System.out.println("찾음");
            return new CustomUserDetails(userEntity);
        }
        System.out.println("못 찾음");
        return null;
    }
}
