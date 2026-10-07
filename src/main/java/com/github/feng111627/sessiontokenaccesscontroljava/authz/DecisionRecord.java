package com.github.feng111627.sessiontokenaccesscontroljava.authz;

import java.time.Instant;
import java.util.Set;

/**
 * 一次鉴权判定的完整记录：请求要素（含当时令牌中的角色）+ 所用策略版本 + 结论与理由。
 * 记录是自包含的：凭 policyVersion 找到当时的规则快照即可离线复算同一结论。
 */
public record DecisionRecord(long sequence, Instant at, String subject, Set<String> roles,
                             String path, String scope,
                             Outcome outcome, String policyVersion, String ruleId, String reason) {

    public enum Outcome {
        /** 未认证（无令牌或令牌无效） */
        UNAUTHENTICATED,
        /** 已认证但越权 */
        FORBIDDEN,
        /** 放行 */
        PERMITTED
    }
}
