package com.github.feng111627.sessiontokenaccesscontroljava.auth;

import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthErrorCode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthException;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

/**
 * 登录失败限流与临时锁定。
 * <p>规则：同一账号或同一来源连续失败达到 maxFailures 次即锁定 lockMillis 毫秒；
 * 锁定到期后自动解锁（惰性评估，无需后台线程）；登录成功立即清零对应计数。
 * 所有计数与状态在内部锁下读写，并发登录不会绕过限流。</p>
 */
public class LoginAttemptGuard {

    private record Counter(int failures, long lockedUntilEpochMs) {
        static Counter empty() { return new Counter(0, 0L); }
    }

    private final int maxFailures;
    private final long lockMillis;
    private final Clock clock;
    private final Map<String, Counter> byAccount = new HashMap<>();
    private final Map<String, Counter> bySource = new HashMap<>();
    private final Object lock = new Object();

    public LoginAttemptGuard(int maxFailures, long lockMillis, Clock clock) {
        this.maxFailures = maxFailures;
        this.lockMillis = lockMillis;
        this.clock = clock;
    }

    /** 若账号或来源处于锁定期则抛出带明确原因码的异常。 */
    public void checkNotLocked(String username, String source) {
        synchronized (lock) {
            long now = clock.millis();
            long accountUntil = activeLockUntil(byAccount.get(username), now);
            if (accountUntil > now) {
                throw new AuthException(AuthErrorCode.ACCOUNT_LOCKED,
                        "account locked until " + accountUntil);
            }
            long sourceUntil = activeLockUntil(bySource.get(source), now);
            if (sourceUntil > now) {
                throw new AuthException(AuthErrorCode.SOURCE_LOCKED,
                        "source locked until " + sourceUntil);
            }
        }
    }

    public void onSuccess(String username, String source) {
        synchronized (lock) {
            byAccount.remove(username);
            bySource.remove(source);
        }
    }

    public void onFailure(String username, String source) {
        synchronized (lock) {
            long now = clock.millis();
            bump(byAccount, username, now);
            bump(bySource, source, now);
        }
    }

    /** 返回当前仍生效的锁定截止时间（未锁定返回 0），用于测试与排障。 */
    public long lockedUntilEpochMs(String username, String source) {
        synchronized (lock) {
            long now = clock.millis();
            return Math.max(activeLockUntil(byAccount.get(username), now),
                            activeLockUntil(bySource.get(source), now));
        }
    }

    private void bump(Map<String, Counter> map, String key, long now) {
        Counter c = map.getOrDefault(key, Counter.empty());
        // 上一次锁定已过期则重新计数
        int failures = (c.lockedUntilEpochMs() > now) ? c.failures() : c.failures();
        failures = c.failures() + 1;
        long lockedUntil = failures >= maxFailures ? now + lockMillis : 0L;
        map.put(key, new Counter(failures, lockedUntil));
    }

    private static long activeLockUntil(Counter c, long now) {
        if (c == null || c.lockedUntilEpochMs() <= now) {
            return 0L;
        }
        return c.lockedUntilEpochMs();
    }
}
