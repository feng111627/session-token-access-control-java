package com.github.feng111627.sessiontokenaccesscontroljava.auth;

import com.github.feng111627.sessiontokenaccesscontroljava.support.TimeProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;

/**
 * 登录失败限流与临时锁定。
 *
 * 规则（均可配置）：
 * <ul>
 *   <li>同一账号在窗口内连续失败达到阈值 → 锁定账号，锁定时长固定</li>
 *   <li>同一来源（IP）在窗口内累计失败达到阈值 → 该来源被限流，时长固定</li>
 *   <li>锁定/限流到期后自动解除；登录成功会清零该账号的失败计数</li>
 * </ul>
 * 核心入口 {@link #attempt} 把“前置检查 → 凭据验证 → 计数/清零”放在同一把锁内，
 * 并发登录既不会绕过阈值，也不会出现计数与状态不一致。
 */
@Component
public class LoginAttemptLimiter {

    private final TimeProvider timeProvider;
    private final int maxFailuresPerAccount;
    private final int maxFailuresPerSource;
    private final long windowSeconds;
    private final long lockSeconds;

    private final Map<String, Counter> byAccount = new ConcurrentHashMap<>();
    private final Map<String, Counter> bySource = new ConcurrentHashMap<>();

    public LoginAttemptLimiter(TimeProvider timeProvider,
                               @Value("${security.login.max-failures-per-account:5}") int maxFailuresPerAccount,
                               @Value("${security.login.max-failures-per-source:20}") int maxFailuresPerSource,
                               @Value("${security.login.window-seconds:600}") long windowSeconds,
                               @Value("${security.login.lock-seconds:300}") long lockSeconds) {
        this.timeProvider = timeProvider;
        this.maxFailuresPerAccount = maxFailuresPerAccount;
        this.maxFailuresPerSource = maxFailuresPerSource;
        this.windowSeconds = windowSeconds;
        this.lockSeconds = lockSeconds;
    }

    private static final class Counter {
        int failures;
        Instant windowStart;
        Instant blockedUntil; // 锁定/限流截止时间

        Counter(Instant now) {
            this.windowStart = now;
        }
    }

    /**
     * 原子地完成一次登录尝试：先检查锁定/限流，再执行凭据验证，最后按结果计数或清零。
     *
     * @param credentialCheck 凭据验证回调（在锁内执行，应保持轻量）
     * @return 凭据验证结果；true 表示凭据正确
     * @throws AuthException ACCOUNT_LOCKED / RATE_LIMITED（携带 retryAfterSeconds）
     */
    public synchronized boolean attempt(String account, String source, BooleanSupplier credentialCheck) {
        Instant now = timeProvider.now();
        checkAccountAllowed(account, now);
        checkSourceAllowed(source, now);
        boolean ok = credentialCheck.getAsBoolean();
        if (ok) {
            byAccount.remove(account); // 成功清零账号计数；来源计数保留，防止换账号试探
        } else {
            recordFailure(account, source, now);
        }
        return ok;
    }

    /** 查询账号剩余锁定秒数；未锁定返回 0。主要用于可观测性与测试。 */
    public synchronized long accountLockRemainingSeconds(String account) {
        Counter acc = byAccount.get(account);
        if (acc == null || acc.blockedUntil == null) return 0;
        return Math.max(0, secondsBetween(timeProvider.now(), acc.blockedUntil));
    }

    private void checkAccountAllowed(String account, Instant now) {
        Counter acc = byAccount.get(account);
        if (acc == null || acc.blockedUntil == null) return;
        if (now.isBefore(acc.blockedUntil)) {
            throw new AuthException(AuthException.Kind.ACCOUNT_LOCKED,
                    "account '" + account + "' is locked",
                    secondsBetween(now, acc.blockedUntil));
        }
        byAccount.remove(account); // 到期自动解锁
    }

    private void checkSourceAllowed(String source, Instant now) {
        Counter src = bySource.get(source);
        if (src == null || src.blockedUntil == null) return;
        if (now.isBefore(src.blockedUntil)) {
            throw new AuthException(AuthException.Kind.RATE_LIMITED,
                    "source '" + source + "' is rate limited",
                    secondsBetween(now, src.blockedUntil));
        }
        bySource.remove(source);
    }

    private void recordFailure(String account, String source, Instant now) {
        Counter acc = byAccount.computeIfAbsent(account, k -> new Counter(now));
        if (bump(acc, now) >= maxFailuresPerAccount) {
            acc.blockedUntil = now.plusSeconds(lockSeconds);
        }
        Counter src = bySource.computeIfAbsent(source, k -> new Counter(now));
        if (bump(src, now) >= maxFailuresPerSource) {
            src.blockedUntil = now.plusSeconds(lockSeconds);
        }
    }

    private int bump(Counter c, Instant now) {
        if (now.isAfter(c.windowStart.plusSeconds(windowSeconds))) {
            c.failures = 0;
            c.windowStart = now;
        }
        return ++c.failures;
    }

    private static long secondsBetween(Instant from, Instant to) {
        return Math.max(1, to.getEpochSecond() - from.getEpochSecond());
    }
}
