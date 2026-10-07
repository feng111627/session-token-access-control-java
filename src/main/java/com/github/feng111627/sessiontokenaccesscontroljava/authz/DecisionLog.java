package com.github.feng111627.sessiontokenaccesscontroljava.authz;

import com.github.feng111627.sessiontokenaccesscontroljava.support.TimeProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 判定日志：内存保留全部判定记录，同时输出到应用日志，保证每条判定可解释、可复算。
 */
@Component
public class DecisionLog {

    private static final Logger log = LoggerFactory.getLogger(DecisionLog.class);

    private final AtomicLong sequence = new AtomicLong();
    private final List<DecisionRecord> records = new CopyOnWriteArrayList<>();

    public DecisionRecord append(DecisionRecord.Outcome outcome, String subject, Set<String> roles,
                                 String path, String scope, String policyVersion, String ruleId,
                                 String reason, TimeProvider timeProvider) {
        DecisionRecord record = new DecisionRecord(sequence.incrementAndGet(), timeProvider.now(),
                subject, roles == null ? Set.of() : Set.copyOf(roles),
                path, scope, outcome, policyVersion, ruleId, reason);
        records.add(record);
        log.info("authz decision #{} subject={} roles={} path={} scope={} outcome={} policyVersion={} rule={} reason={}",
                record.sequence(), subject, record.roles(), path, scope, outcome, policyVersion, ruleId, reason);
        return record;
    }

    public List<DecisionRecord> all() {
        return List.copyOf(records);
    }
}
