package com.example.Spring_JWT.controller;

import com.example.Spring_JWT.util.SecurityContextUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Iterator;

@RestController
public class MainController {

    @GetMapping("/")
    public String mainP(HttpServletResponse response) {
        System.out.println("JWT log: " + "MainController mainP");
        String userInfo = SecurityContextUtil.getUserInfoBySecurityContext(response);
        System.out.println("userInfo: " + userInfo);
        return "main Controller" + userInfo;
    }

}