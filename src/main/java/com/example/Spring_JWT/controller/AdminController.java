package com.example.Spring_JWT.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class AdminController {

    @GetMapping("/admin")
    public String adminP() {
        System.out.println("JWT log: " + "AdminController adminP");
        return "admin Controller";
    }
}
