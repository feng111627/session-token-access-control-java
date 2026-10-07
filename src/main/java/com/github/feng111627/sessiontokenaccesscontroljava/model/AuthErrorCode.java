package com.github.feng111627.sessiontokenaccesscontroljava.model;

/**
 * 可区分的认证/鉴权失败原因码。
 */
public enum AuthErrorCode {
    INVALID_CREDENTIALS,
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,
    SOURCE_LOCKED,
    TOKEN_MALFORMED,
    TOKEN_TAMPERED,
    TOKEN_EXPIRED,
    REFRESH_TOKEN_UNKNOWN,
    REFRESH_TOKEN_REUSED,
    REFRESH_TOKEN_EXPIRED,
    UNAUTHENTICATED,
    FORBIDDEN,
    RESOURCE_NOT_FOUND
}
