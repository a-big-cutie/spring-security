package org.springsecurity.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springsecurity.config.JwtUtil;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;

    private final JwtUtil jwtUtil;

    public AuthService(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    /**
     * 用户登录并生成 JWT Token
     *
     * 调用 authenticationManager.authenticate() 验证用户凭据
     * 如果认证成功，提取用户名并生成 JWT
     *
     * @param username
     * @param password
     * @return
     */
    public String login(String username, String password) {

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            return jwtUtil.generateToken(authentication.getName());
        } catch (AuthenticationException e) {
            // 记录日志或返回详细错误信息
            throw new BadCredentialsException("Invalid username or password");
        }
    }
}
