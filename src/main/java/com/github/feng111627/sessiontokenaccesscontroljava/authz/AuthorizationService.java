package com.github.feng111627.sessiontokenaccesscontroljava.authz;

import com.github.feng111627.sessiontokenaccesscontroljava.auth.TokenService;
import com.github.feng111627.sessiontokenaccesscontroljava.support.TimeProvider;
import org.springframework.stereotype.Service;

/**
 * 鉴权判定：基于当前策略版本评估“角色 + 资源范围”，并记录判定日志。
 * 判定是纯函数（策略快照 × 请求要素），与请求顺序、重启无关，可复现。
 */
@Service
public class AuthorizationService {

    private final PolicyRegistry policyRegistry;
    private final DecisionLog decisionLog;
    private final TimeProvider timeProvider;

    public AuthorizationService(PolicyRegistry policyRegistry, DecisionLog decisionLog, TimeProvider timeProvider) {
        this.policyRegistry = policyRegistry;
        this.decisionLog = decisionLog;
        this.timeProvider = timeProvider;
    }

    /** 对未认证请求的判定记录。 */
    public DecisionRecord denyUnauthenticated(String path, String scope, String reason) {
        AccessPolicy policy = policyRegistry.current();
        return decisionLog.append(DecisionRecord.Outcome.UNAUTHENTICATED, null, null, path, scope,
                policy.version(), null, reason, timeProvider);
    }

    /** 对已认证请求的判定：返回判定记录，outcome 为 PERMITTED 或 FORBIDDEN。 */
    public DecisionRecord authorize(TokenService.AccessToken token, String path, String scope) {
        AccessPolicy policy = policyRegistry.current();
        return evaluate(policy, token.subject(), token.roles(), path, scope, true);
    }

    /**
     * 复算历史判定：用记录中保存的策略版本快照与角色集合，对同一请求要素重新评估。
     * 结果应与记录中的 outcome 一致；策略版本已不存在时返回 null。
     */
    public DecisionRecord.Outcome replay(DecisionRecord record) {
        AccessPolicy snapshot = policyRegistry.byVersion(record.policyVersion());
        if (snapshot == null) return null;
        if (record.outcome() == DecisionRecord.Outcome.UNAUTHENTICATED) {
            return DecisionRecord.Outcome.UNAUTHENTICATED; // 未认证判定与规则内容无关
        }
        return evaluate(snapshot, record.subject(), record.roles(), record.path(), record.scope(), false)
                .outcome();
    }

    private DecisionRecord evaluate(AccessPolicy policy, String subject, java.util.Set<String> roles,
                                    String path, String scope, boolean writeLog) {
        PolicyRule rule = policy.firstMatching(path, scope);
        DecisionRecord.Outcome outcome;
        String ruleId;
        String reason;
        if (rule == null) {
            outcome = DecisionRecord.Outcome.FORBIDDEN;
            ruleId = null;
            reason = "no rule matches; default deny";
        } else if (rule.roles().isEmpty() || rule.roles().stream().anyMatch(roles::contains)) {
            outcome = DecisionRecord.Outcome.PERMITTED;
            ruleId = rule.id();
            reason = "role matched";
        } else {
            outcome = DecisionRecord.Outcome.FORBIDDEN;
            ruleId = rule.id();
            reason = "requires one of " + rule.roles() + " but subject has " + roles;
        }
        if (!writeLog) {
            return new DecisionRecord(0, null, subject, roles, path, scope, outcome, policy.version(), ruleId, reason);
        }
        return decisionLog.append(outcome, subject, roles, path, scope, policy.version(), ruleId, reason, timeProvider);
    }
}
