package com.github.feng111627.sessiontokenaccesscontroljava.web;

import com.github.feng111627.sessiontokenaccesscontroljava.auth.AuthService;
import com.github.feng111627.sessiontokenaccesscontroljava.model.TokenPair;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 登录与刷新入口。
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    public record LoginRequest(String username, String password) {}
    public record RefreshRequest(String refreshToken) {}

    @PostMapping("/login")
    public TokenPair login(@RequestBody LoginRequest request, HttpServletRequest http) {
        return authService.login(request.username(), request.password(), clientSource(http));
    }

    @PostMapping("/refresh")
    public TokenPair refresh(@RequestBody RefreshRequest request) {
        return authService.refresh(request.refreshToken());
    }

    static String clientSource(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
