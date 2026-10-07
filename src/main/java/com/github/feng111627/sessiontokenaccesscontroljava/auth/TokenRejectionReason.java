package com.github.feng111627.sessiontokenaccesscontroljava.auth;

/**
 * 令牌被拒绝的具体原因。各类原因必须可区分，不允许一律返回含糊错误。
 */
public enum TokenRejectionReason {
    /** 令牌格式无法解析 */
    MALFORMED,
    /** 签名校验失败，令牌被篡改 */
    TAMPERED,
    /** 令牌已过有效期 */
    EXPIRED,
    /** 刷新令牌已被使用过（重放），本次轮换链已被吊销 */
    REUSED,
    /** 刷新令牌在服务端不存在（已吊销或从未签发） */
    UNKNOWN_REFRESH_TOKEN,
    /** 令牌所属账号已被停用 */
    ACCOUNT_DISABLED,
    /** 令牌类型用错（如把访问令牌当刷新令牌提交） */
    WRONG_TOKEN_TYPE
}
