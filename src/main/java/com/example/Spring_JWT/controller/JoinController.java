package com.example.Spring_JWT.controller;

import com.example.Spring_JWT.dto.JoinDTO;
import com.example.Spring_JWT.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(@RequestBody JoinDTO joinDTO) {
        System.out.println("JWT log: " + "JoinController joinProcess");
        joinService.joinProcess(joinDTO);
        return "ok";
    }
}
