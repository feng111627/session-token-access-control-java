package com.github.feng111627.sessiontokenaccesscontroljava.access;

import java.util.Set;

/**
 * 一条鉴权规则：资源 + 动作 所需的角色集合（任一满足即可）。
 */
public record AccessRule(String resource, String action, Set<String> requiredRoles) {
}
