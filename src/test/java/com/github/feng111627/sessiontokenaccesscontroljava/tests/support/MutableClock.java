package com.github.feng111627.sessiontokenaccesscontroljava.tests.support;

import com.github.feng111627.sessiontokenaccesscontroljava.support.TimeProvider;

import java.time.Instant;

/** 可手动推进的测试时钟，用于验证过期、锁定与自动解锁的时间语义。 */
public class MutableClock implements TimeProvider {

    private Instant now;

    public MutableClock() {
        this(Instant.parse("2026-10-07T00:00:00Z"));
    }

    public MutableClock(Instant start) {
        this.now = start;
    }

    @Override
    public Instant now() {
        return now;
    }

    public void advanceSeconds(long seconds) {
        now = now.plusSeconds(seconds);
    }
}
