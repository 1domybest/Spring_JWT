package com.example.Spring_JWT.dto;


import com.example.Spring_JWT.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;


// 유저정보로 비지니스 로직 가공 내가 override를 사용해서 쓸수도있지만 추가로 내가 필요한 값을 추가할수있음
// 예를들어 memberId 같은것
@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final UserEntity userEntity;

    // ROLE 값을 반환하는 함수
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return userEntity.getRole();
            }
        });

        return collection;
    }

    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    public Long getMemberId() {
        return userEntity.getId();
    }

    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
