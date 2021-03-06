package com.jwt.practice.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @PostMapping("/test")
    public String test() {
        return "Authorization Success!"; // Rest Controller 이기 때문에, String 을 반환 , Security 통과를 하면 성공
    }

    @PostMapping("/user")
    public String user() { // User 가 접속 가능 (User 정보에서, ROLE 을 확인해서)
        return "Authorization Success!";
    }

    @PostMapping("/admin")
    public String admin() { // Admin 이 접속 가능 (User 정보에서, ROLE 을 확인해서)
        return "Authorization Success!";
    }
}