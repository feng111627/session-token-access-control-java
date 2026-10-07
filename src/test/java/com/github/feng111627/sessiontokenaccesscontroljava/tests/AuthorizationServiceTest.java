package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import com.github.feng111627.sessiontokenaccesscontroljava.access.AccessPolicy;
import com.github.feng111627.sessiontokenaccesscontroljava.access.AccessResult;
import com.github.feng111627.sessiontokenaccesscontroljava.access.AuthorizationService;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AccessTokenClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 业务域：基于角色与资源范围的鉴权（可区分结论 + 判定可复现）。
 */
class AuthorizationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServiceTest.class);

    private AuthorizationService service;

    @BeforeEach
    void setUp(TestInfo info) {
        AccessPolicy policy = AccessPolicy.parse("v1",
                List.of("documents:read:USER,ADMIN", "documents:write:ADMIN", "admin-console:read:ADMIN"),
                List.of("documents", "admin-console"));
        service = new AuthorizationService(policy);
        log.info("[鉴权] 用例: {}", info.getDisplayName());
    }

    private static AccessTokenClaims user(String name, String... roles) {
        return new AccessTokenClaims(name, Set.of(roles), 0, Long.MAX_VALUE, "jti");
    }

    @Test
    @DisplayName("角色匹配资源范围 -> ALLOW，结论携带规则版本")
    void allowWhenRoleMatches() {
        AccessResult r = service.evaluate(user("alice", "USER"), "documents", "read");
        assertEquals(AccessResult.Decision.ALLOW, r.decision());
        assertEquals("v1", r.ruleVersion());
        log.info("[鉴权] ALLOW, ruleVersion={}", r.ruleVersion());
    }

    @Test
    @DisplayName("已认证但角色不足 -> FORBIDDEN")
    void forbiddenWhenRoleInsufficient() {
        AccessResult r = service.evaluate(user("alice", "USER"), "documents", "write");
        assertEquals(AccessResult.Decision.FORBIDDEN, r.decision());
        AccessResult r2 = service.evaluate(user("alice", "USER"), "admin-console", "read");
        assertEquals(AccessResult.Decision.FORBIDDEN, r2.decision());
        log.info("[鉴权] FORBIDDEN, detail={}", r.detail());
    }

    @Test
    @DisplayName("未认证 -> UNAUTHENTICATED，与越权可区分")
    void unauthenticatedIsDistinct() {
        AccessResult r = service.evaluate(null, "documents", "read");
        assertEquals(AccessResult.Decision.UNAUTHENTICATED, r.decision());
        log.info("[鉴权] UNAUTHENTICATED");
    }

    @Test
    @DisplayName("资源不存在 -> RESOURCE_NOT_FOUND，与越权可区分")
    void unknownResourceIsDistinct() {
        AccessResult r = service.evaluate(user("alice", "USER", "ADMIN"), "ghost", "read");
        assertEquals(AccessResult.Decision.RESOURCE_NOT_FOUND, r.decision());
        log.info("[鉴权] RESOURCE_NOT_FOUND");
    }

    @Test
    @DisplayName("同一请求在相同规则版本下判定可复现，与评估次数和顺序无关")
    void decisionsAreReproducible() {
        AccessResult first = service.evaluate(user("alice", "USER"), "documents", "write");
        // 打乱顺序先评估别的请求，再重复同一请求
        service.evaluate(user("admin", "ADMIN"), "admin-console", "read");
        service.evaluate(user("alice", "USER"), "documents", "read");
        AccessResult repeated = service.evaluate(user("alice", "USER"), "documents", "write");
        assertEquals(first, repeated, "同样输入+同样规则版本 => 同样结论");
        // 换一个全新实例（模拟重启）结论仍一致
        AuthorizationService restarted = new AuthorizationService(AccessPolicy.parse("v1",
                List.of("documents:read:USER,ADMIN", "documents:write:ADMIN", "admin-console:read:ADMIN"),
                List.of("documents", "admin-console")));
        assertEquals(first, restarted.evaluate(user("alice", "USER"), "documents", "write"));
        log.info("[鉴权] 判定可复现: {}", first);
    }

    @Test
    @DisplayName("规则版本变更后结论可随版本区分，历史版本判定仍可复现")
    void ruleVersionChangeIsTraceable() {
        AccessResult before = service.evaluate(user("alice", "USER"), "documents", "write");
        AuthorizationService v2 = new AuthorizationService(AccessPolicy.parse("v2",
                List.of("documents:read:USER,ADMIN", "documents:write:USER,ADMIN", "admin-console:read:ADMIN"),
                List.of("documents", "admin-console")));
        AccessResult after = v2.evaluate(user("alice", "USER"), "documents", "write");
        assertEquals(AccessResult.Decision.FORBIDDEN, before.decision());
        assertEquals(AccessResult.Decision.ALLOW, after.decision());
        assertEquals("v1", before.ruleVersion());
        assertEquals("v2", after.ruleVersion());
        // 用 v1 策略重放历史请求，结论与当初一致
        assertEquals(before, service.evaluate(user("alice", "USER"), "documents", "write"));
        log.info("[鉴权] 版本迁移: v1={} -> v2={}", before.decision(), after.decision());
    }
}
