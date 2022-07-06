package com.jwt.practice.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @PostMapping("/test")
    public String test(){
        return "Authorization Success!"; // Rest Controller 이기 때문에, String 을 반환 , Security 통과를 하면 성공
    }
}