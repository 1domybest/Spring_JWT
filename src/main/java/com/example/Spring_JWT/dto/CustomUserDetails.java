package com.example.Spring_JWT.dto;


import com.example.Spring_JWT.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;


/**
 * @see UserDetails
 * 시큐리티에서 제공하는 유저에대한 정보를 약속하에 UserDetails 라는 객체로 제공
 * 이 타입을 토대로 @Override 하여 제공하는 setter 에 검증에 필요한 값을 넣고 getter 할수있다.
 * 또한 추가로 커스텀하여 유저 Entity 에서 원하는 정보 반환하는 함수도 지정이 가능
 */
@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final UserEntity userEntity;

    /**
     * UserDetails 에 저장되어있는 ROLE 값을 반환하는 함수
     * @return String
     */
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

    /**
     * UserDetails 에 저장되어있는 비밀번호 값을 반환하는 함수
     * @return String password
     */
    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    /**
     * UserEntity 에 저장되어있는 ID(PK) 값을 반환하는 함수
     * @return Long userEntity PK
     */
    public Long getMemberId() {
        return userEntity.getId();
    }

    /**
     * UserDetails 에 저장되어있는 Username 값을 반환하는 함수
     * @return String username
     */
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
