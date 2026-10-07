package com.github.feng111627.sessiontokenaccesscontroljava.authz;

import java.util.Set;

/**
 * 一条鉴权规则：匹配某类资源路径，要求指定角色与资源范围。
 *
 * @param id          规则 id（判定结果中回引，便于解释）
 * @param pathPattern 路径模式，支持 {@code *}（单段通配）与 {@code **}（任意后缀）
 * @param roles       允许的角色集合，任一命中即可；空集表示仅要求已认证
 * @param scope       资源范围：read / write / any
 */
public record PolicyRule(String id, String pathPattern, Set<String> roles, String scope) {

    public boolean matchesPath(String path) {
        if (pathPattern.endsWith("/**")) {
            return path.startsWith(pathPattern.substring(0, pathPattern.length() - 3));
        }
        if (pathPattern.contains("*")) {
            String regex = java.util.regex.Pattern.quote(pathPattern).replace("*", "\\E[^/]*\\Q");
            return path.matches(regex);
        }
        return pathPattern.equals(path);
    }

    public boolean coversScope(String requiredScope) {
        return "any".equals(scope) || scope.equals(requiredScope);
    }
}
