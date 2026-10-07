package com.github.feng111627.sessiontokenaccesscontroljava.web;

import com.github.feng111627.sessiontokenaccesscontroljava.auth.AuthException;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 认证入口：登录、刷新、登出。失败响应用不同的 error 码区分原因。
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
    public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletRequest http) {
        String source = http.getRemoteAddr() == null ? "unknown" : http.getRemoteAddr();
        AuthService.TokenPair pair = authService.login(req.username(), req.password(), source);
        return ResponseEntity.ok(tokenBody(pair));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest req) {
        AuthService.TokenPair pair = authService.refresh(req.refreshToken());
        return ResponseEntity.ok(tokenBody(pair));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> body) {
        authService.logout(body.get("username"));
        return ResponseEntity.ok(Map.of("status", "ok"));
    }

    private Map<String, Object> tokenBody(AuthService.TokenPair pair) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accessToken", pair.accessToken());
        body.put("refreshToken", pair.refreshToken());
        body.put("accessExpiresInSeconds", pair.accessExpiresInSeconds());
        body.put("refreshExpiresInSeconds", pair.refreshExpiresInSeconds());
        return body;
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<?> onAuthException(AuthException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        int status = switch (e.kind()) {
            case BAD_CREDENTIALS -> { body.put("error", "INVALID_CREDENTIALS"); yield 401; }
            case ACCOUNT_DISABLED -> { body.put("error", "ACCOUNT_DISABLED"); yield 403; }
            case ACCOUNT_LOCKED -> { body.put("error", "ACCOUNT_LOCKED"); yield 423; }
            case RATE_LIMITED -> { body.put("error", "RATE_LIMITED"); yield 429; }
            case TOKEN_REJECTED -> {
                body.put("error", "TOKEN_REJECTED");
                body.put("tokenRejectionReason", e.tokenRejectionReason().name());
                yield 401;
            }
        };
        body.put("message", e.getMessage());
        if (e.retryAfterSeconds() != null) body.put("retryAfterSeconds", e.retryAfterSeconds());
        return ResponseEntity.status(status).body(body);
    }
}
