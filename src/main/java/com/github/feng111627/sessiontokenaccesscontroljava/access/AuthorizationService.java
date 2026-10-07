package com.github.feng111627.sessiontokenaccesscontroljava.access;

import com.github.feng111627.sessiontokenaccesscontroljava.model.AccessTokenClaims;

import java.util.List;

/**
 * 基于角色与资源范围的鉴权评估。
 * <p>评估是关于 (claims, resource, action, policy) 的纯函数：同样的输入与规则版本
 * 必然得到同样的结论，与重启、请求顺序无关；结论中携带规则版本便于复现历史判定。</p>
 */
public class AuthorizationService {

    private final AccessPolicy policy;

    public AuthorizationService(String ruleVersion, List<AccessRule> rules, List<String> knownResources) {
        this(new AccessPolicy(ruleVersion, List.copyOf(rules), java.util.Set.copyOf(knownResources)));
    }

    public AuthorizationService(AccessPolicy policy) {
        this.policy = policy;
    }

    /**
     * @param claims 已认证的令牌声明；null 表示未认证
     */
    public AccessResult evaluate(AccessTokenClaims claims, String resource, String action) {
        if (claims == null) {
            return new AccessResult(AccessResult.Decision.UNAUTHENTICATED, policy.version(),
                    "no authenticated principal");
        }
        if (!policy.knownResources().contains(resource)) {
            return new AccessResult(AccessResult.Decision.RESOURCE_NOT_FOUND, policy.version(),
                    "unknown resource: " + resource);
        }
        List<AccessRule> matching = policy.rules().stream()
                .filter(r -> r.resource().equals(resource) && r.action().equals(action))
                .toList();
        if (matching.isEmpty()) {
            return new AccessResult(AccessResult.Decision.FORBIDDEN, policy.version(),
                    "no rule grants " + action + " on " + resource);
        }
        boolean granted = matching.stream().anyMatch(r ->
                r.requiredRoles().stream().anyMatch(claims.roles()::contains));
        return granted
                ? AccessResult.allow(policy.version())
                : new AccessResult(AccessResult.Decision.FORBIDDEN, policy.version(),
                        "roles " + claims.roles() + " insufficient for " + action + " on " + resource);
    }

    public String getRuleVersion() {
        return policy.version();
    }
}
