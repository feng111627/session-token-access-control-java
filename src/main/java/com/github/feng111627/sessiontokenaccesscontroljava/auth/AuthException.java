package com.github.feng111627.sessiontokenaccesscontroljava.auth;

/**
 * 认证/刷新失败的业务异常，携带可区分的失败原因。
 */
public class AuthException extends RuntimeException {

    public enum Kind {
        BAD_CREDENTIALS,
        ACCOUNT_LOCKED,
        RATE_LIMITED,
        ACCOUNT_DISABLED,
        TOKEN_REJECTED
    }

    private final Kind kind;
    private final TokenRejectionReason tokenRejectionReason; // 仅 TOKEN_REJECTED 时有值
    private final Long retryAfterSeconds;                    // 锁定/限流时给出可预期的等待时间

    public AuthException(Kind kind, String message) {
        this(kind, message, null, null);
    }

    public AuthException(Kind kind, String message, Long retryAfterSeconds) {
        this(kind, message, null, retryAfterSeconds);
    }

    public AuthException(TokenRejectionReason reason, String message) {
        this(Kind.TOKEN_REJECTED, message, reason, null);
    }

    private AuthException(Kind kind, String message, TokenRejectionReason reason, Long retryAfterSeconds) {
        super(message);
        this.kind = kind;
        this.tokenRejectionReason = reason;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public Kind kind() { return kind; }
    public TokenRejectionReason tokenRejectionReason() { return tokenRejectionReason; }
    public Long retryAfterSeconds() { return retryAfterSeconds; }
}
