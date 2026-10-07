package com.github.feng111627.sessiontokenaccesscontroljava.model;

/**
 * 登录或刷新成功后颁发的令牌对。
 */
public record TokenPair(String accessToken, String refreshToken,
                        long accessTokenExpiresAtEpochMs, long refreshTokenExpiresAtEpochMs) {
}
