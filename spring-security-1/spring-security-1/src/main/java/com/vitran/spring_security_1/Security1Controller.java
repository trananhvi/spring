package com.vitran.spring_security_1;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rest")
public class Security1Controller {
    @GetMapping("/public")
    public String publicEndpoint() {
        return "this is public";
    }
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "this is admin";
    }
    @GetMapping("/user")
    public String userEndpoint() {
        return "this is user";
    }
}
