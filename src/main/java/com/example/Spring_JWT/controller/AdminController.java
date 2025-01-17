package com.example.Spring_JWT.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {

    @GetMapping("/admin")
    public String adminP() {
        System.out.println("JWT log: " + "AdminController adminP");
        return "admin Controller";
    }
}
