package com.github.feng111627.sessiontokenaccesscontroljava.support;

import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class SystemTimeProvider implements TimeProvider {
    @Override
    public Instant now() {
        return Instant.now();
    }
}
