package com.github.feng111627.sessiontokenaccesscontroljava.access;

/**
 * 鉴权结论：可区分 未认证 / 越权 / 资源不存在 / 允许，并记录判定所用的规则版本以便复现。
 */
public record AccessResult(Decision decision, String ruleVersion, String detail) {

    public enum Decision {
        ALLOW, UNAUTHENTICATED, FORBIDDEN, RESOURCE_NOT_FOUND
    }

    public static AccessResult allow(String ruleVersion) {
        return new AccessResult(Decision.ALLOW, ruleVersion, "allowed");
    }
}
