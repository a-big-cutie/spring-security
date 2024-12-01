package org.springsecurity.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 *  加载用户的详细信息（如用户名、密码、权限）供 Spring Security 使用
 *  模拟从数据库中加载用户
 */
@Service
public class CustomerUserDetailsService implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 定义了用户的用户名和密码
     *
     * 验证传入的用户名是否存在。
     * 提供用户的角色和权限信息
     *
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 在这里根据用户名加载用户数据或者从数据库加载
        if ("user".equals(username)) {
            return User.builder()
                    .username("user")
                    .password(passwordEncoder.encode("password"))
                    .roles("USER")
                    .build();
        }
       throw new UsernameNotFoundException("User not found");
    }
}
