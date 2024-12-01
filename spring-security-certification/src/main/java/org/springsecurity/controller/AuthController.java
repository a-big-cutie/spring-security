package org.springsecurity.controller;

import org.springframework.web.bind.annotation.*;
import org.springsecurity.entity.AuthRequest;
import org.springsecurity.service.AuthService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController (AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public String login (@RequestBody AuthRequest authRequest) {
        return authService.login(authRequest.getUsername(), authRequest.getPassword());
    }

    @GetMapping("/secure-endpoint")
    public String secureEndpoint() {
        return "You have accessed a secure endpoint!";
    }
}
