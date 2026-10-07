package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import com.github.feng111627.sessiontokenaccesscontroljava.auth.TokenService;
import com.github.feng111627.sessiontokenaccesscontroljava.authz.*;
import com.github.feng111627.sessiontokenaccesscontroljava.tests.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("鉴权：角色+范围判定、默认拒绝、判定可复现")
class AuthorizationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServiceTest.class);

    private MutableClock clock;
    private PolicyProperties properties;
    private PolicyRegistry registry;
    private DecisionLog decisionLog;
    private AuthorizationService authz;
    private TokenService tokens;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        properties = new PolicyProperties();
        properties.setRules(List.of(rule("docs-read", "/api/documents/**", Set.of("ROLE_USER"), "read"),
                rule("admin", "/api/admin/**", Set.of("ROLE_ADMIN"), "any")));
        registry = new PolicyRegistry(properties);
        decisionLog = new DecisionLog();
        authz = new AuthorizationService(registry, decisionLog, clock);
        tokens = new TokenService(clock, "test-secret", 300);
    }

    private static PolicyProperties.Rule rule(String id, String path, Set<String> roles, String scope) {
        PolicyProperties.Rule r = new PolicyProperties.Rule();
        r.setId(id);
        r.setPath(path);
        r.setRoles(roles);
        r.setScope(scope);
        return r;
    }

    private TokenService.AccessToken token(String subject, String... roles) {
        return tokens.verifyAccessToken(tokens.issueAccessToken(subject, Set.of(roles)));
    }

    @Test
    @DisplayName("角色匹配且范围匹配 → PERMITTED，判定记录含规则与版本")
    void permitted() {
        log.info("CASE 放行: ROLE_USER 读 /api/documents/1, 期望 PERMITTED + rule=docs-read");
        DecisionRecord d = authz.authorize(token("alice", "ROLE_USER"), "/api/documents/1", "read");
        assertEquals(DecisionRecord.Outcome.PERMITTED, d.outcome());
        assertEquals("docs-read", d.ruleId());
        assertEquals(registry.current().version(), d.policyVersion());
    }

    @Test
    @DisplayName("已认证但角色不足 → FORBIDDEN，与未认证区分")
    void forbiddenWhenRoleMissing() {
        log.info("CASE 越权: ROLE_USER 访问 /api/admin/stats, 期望 FORBIDDEN");
        DecisionRecord d = authz.authorize(token("alice", "ROLE_USER"), "/api/admin/stats", "read");
        assertEquals(DecisionRecord.Outcome.FORBIDDEN, d.outcome());
        assertEquals("admin", d.ruleId());
    }

    @Test
    @DisplayName("范围不匹配 → FORBIDDEN（read 规则不覆盖 write）")
    void forbiddenWhenScopeMismatch() {
        log.info("CASE 范围越权: 仅配 read 的路径提交 write, 期望 FORBIDDEN 默认拒绝");
        DecisionRecord d = authz.authorize(token("alice", "ROLE_USER"), "/api/documents/1", "write");
        assertEquals(DecisionRecord.Outcome.FORBIDDEN, d.outcome());
        assertNull(d.ruleId(), "无规则命中，默认拒绝");
    }

    @Test
    @DisplayName("未认证 → UNAUTHENTICATED 记录")
    void unauthenticated() {
        log.info("CASE 未认证: 期望 UNAUTHENTICATED");
        DecisionRecord d = authz.denyUnauthenticated("/api/documents/1", "read", "missing Bearer token");
        assertEquals(DecisionRecord.Outcome.UNAUTHENTICATED, d.outcome());
    }

    @Test
    @DisplayName("策略版本由内容决定：相同规则集版本相同，不同规则集版本不同")
    void versionIsContentAddressed() {
        log.info("CASE 版本确定性: 同规则→同版本; 改规则→版本变化");
        PolicyRegistry again = new PolicyRegistry(properties);
        assertEquals(registry.current().version(), again.current().version());

        PolicyProperties changed = new PolicyProperties();
        changed.setRules(List.of(rule("docs-read", "/api/documents/**", Set.of("ROLE_USER", "ROLE_ADMIN"), "read")));
        PolicyRegistry other = new PolicyRegistry(changed);
        assertNotEquals(registry.current().version(), other.current().version());
    }

    @Test
    @DisplayName("规则变更后，历史判定可按当时版本复现，结论不漂移")
    void historicalDecisionReproducibleAfterPolicyChange() {
        log.info("CASE 历史复现: 记录一条 FORBIDDEN → 放宽规则 → 用旧版本复算仍为 FORBIDDEN");
        // 1. 当前规则下 alice(ROLE_USER) 访问 admin 路径 → FORBIDDEN
        DecisionRecord original = authz.authorize(token("alice", "ROLE_USER"), "/api/admin/stats", "read");
        assertEquals(DecisionRecord.Outcome.FORBIDDEN, original.outcome());

        // 2. 变更规则：放开 admin 路径给所有人
        PolicyProperties relaxed = new PolicyProperties();
        relaxed.setRules(List.of(rule("docs-read", "/api/documents/**", Set.of("ROLE_USER"), "read"),
                rule("admin", "/api/admin/**", Set.of("ROLE_USER", "ROLE_ADMIN"), "any")));
        registry.reload(relaxed);

        // 3. 新规则下同一请求结论改变
        DecisionRecord now = authz.authorize(token("alice", "ROLE_USER"), "/api/admin/stats", "read");
        assertEquals(DecisionRecord.Outcome.PERMITTED, now.outcome());
        assertNotEquals(original.policyVersion(), now.policyVersion());

        // 4. 用历史记录中的版本复算 → 与历史结论一致
        DecisionRecord.Outcome replayed = authz.replay(original);
        assertEquals(original.outcome(), replayed, "同一请求在历史版本下的复算结论必须一致");
    }

    @Test
    @DisplayName("判定结果与评估顺序无关：同样的请求多次评估结论一致")
    void deterministicRegardlessOfOrder() {
        log.info("CASE 顺序无关: 交错评估不同请求, 相同请求结论一致");
        DecisionRecord a1 = authz.authorize(token("alice", "ROLE_USER"), "/api/documents/1", "read");
        authz.authorize(token("bob", "ROLE_ADMIN"), "/api/admin/stats", "read");
        DecisionRecord a2 = authz.authorize(token("alice", "ROLE_USER"), "/api/documents/1", "read");
        assertEquals(a1.outcome(), a2.outcome());
        assertEquals(a1.ruleId(), a2.ruleId());
        assertEquals(a1.policyVersion(), a2.policyVersion());
    }
}
