package com.github.feng111627.sessiontokenaccesscontroljava.model;

/**
 * 携带明确失败原因码的认证/鉴权异常。
 */
public class AuthException extends RuntimeException {
    private final AuthErrorCode code;

    public AuthException(AuthErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public AuthErrorCode getCode() {
        return code;
    }
}
