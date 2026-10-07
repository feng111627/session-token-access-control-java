package com.github.feng111627.sessiontokenaccesscontroljava.support;

import java.time.Instant;

/**
 * 时间源抽象：业务代码不直接调用系统时钟，
 * 测试可以用可推进的时钟来验证过期、锁定与自动解锁。
 */
public interface TimeProvider {
    Instant now();

    default long nowMillis() {
        return now().toEpochMilli();
    }
}
