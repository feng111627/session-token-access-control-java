package com.github.feng111627.sessiontokenaccesscontroljava.model;

import java.util.Set;

/**
 * 内存中的用户账号。
 */
public record UserAccount(String username, String password, Set<String> roles, boolean enabled) {
}
