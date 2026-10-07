package com.github.feng111627.sessiontokenaccesscontroljava.web;

import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthErrorCode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * 把 AuthException 映射为带明确原因码的 JSON 错误响应，
 * 不同失败原因对应不同的 code 与 HTTP 状态，绝不合并为含糊错误。
 */
@RestControllerAdvice
public class ApiErrorHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handle(AuthException ex) {
        return ResponseEntity.status(statusFor(ex.getCode()))
                .body(Map.of("code", ex.getCode().name(), "message", ex.getMessage()));
    }

    static HttpStatus statusFor(AuthErrorCode code) {
        return switch (code) {
            case INVALID_CREDENTIALS, TOKEN_MALFORMED, TOKEN_TAMPERED, TOKEN_EXPIRED,
                 REFRESH_TOKEN_UNKNOWN, REFRESH_TOKEN_REUSED, REFRESH_TOKEN_EXPIRED,
                 UNAUTHENTICATED -> HttpStatus.UNAUTHORIZED;
            case ACCOUNT_DISABLED, FORBIDDEN -> HttpStatus.FORBIDDEN;
            case ACCOUNT_LOCKED, SOURCE_LOCKED -> HttpStatus.TOO_MANY_REQUESTS;
            case RESOURCE_NOT_FOUND -> HttpStatus.NOT_FOUND;
        };
    }
}
