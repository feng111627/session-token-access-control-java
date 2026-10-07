package com.github.feng111627.sessiontokenaccesscontroljava.auth;

import java.util.Set;

/**
 * 内存中的用户账号。
 *
 * @param username     登录名
 * @param salt         口令盐
 * @param passwordHash 十六进制 SHA-256(salt + password)
 * @param roles        角色集合（如 ROLE_USER / ROLE_ADMIN）
 * @param enabled      是否启用；停用后登录与令牌校验均失败
 */
public record UserAccount(String username, String salt, String passwordHash, Set<String> roles, boolean enabled) {

    public UserAccount withEnabled(boolean newEnabled) {
        return new UserAccount(username, salt, passwordHash, roles, newEnabled);
    }
}
