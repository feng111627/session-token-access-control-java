package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

/** 可手动推进的时钟，让过期与锁定/解锁的边界在测试中可预期。 */
public class MutableClock extends Clock {
    private long millis;
    private final ZoneId zone;

    public MutableClock(long initialMillis) {
        this(initialMillis, ZoneId.of("UTC"));
    }

    private MutableClock(long millis, ZoneId zone) {
        this.millis = millis;
        this.zone = zone;
    }

    public void advanceMillis(long delta) {
        this.millis += delta;
    }

    @Override public ZoneId getZone() { return zone; }
    @Override public Clock withZone(ZoneId zone) { return new MutableClock(millis, zone); }
    @Override public Instant instant() { return Instant.ofEpochMilli(millis); }
    @Override public long millis() { return millis; }
}
