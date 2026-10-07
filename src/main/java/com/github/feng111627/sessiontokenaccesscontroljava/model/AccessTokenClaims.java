package com.github.feng111627.sessiontokenaccesscontroljava.model;

import java.util.Set;

/**
 * 访问令牌解析后的声明。
 */
public record AccessTokenClaims(String subject, Set<String> roles,
                                long issuedAtEpochMs, long expiresAtEpochMs, String tokenId) {
}
