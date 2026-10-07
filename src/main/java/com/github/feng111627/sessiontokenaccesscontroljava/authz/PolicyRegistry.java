package com.github.feng111627.sessiontokenaccesscontroljava.authz;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 策略注册表：当前生效策略 + 历史版本快照。
 * 历史版本保留在内存中，使“按当时的规则版本复算历史判定”成为可能。
 */
@Component
@EnableConfigurationProperties(PolicyProperties.class)
public class PolicyRegistry {

    private final Map<String, AccessPolicy> snapshots = new ConcurrentHashMap<>();
    private volatile AccessPolicy current;

    public PolicyRegistry(PolicyProperties properties) {
        reload(properties);
    }

    /** 从配置重建策略；相同规则集得到相同版本号，重复加载幂等。 */
    public final synchronized void reload(PolicyProperties properties) {
        AccessPolicy policy = AccessPolicy.of(properties.getRules().stream()
                .map(r -> new PolicyRule(r.getId(), r.getPath(), r.getRoles(), r.getScope()))
                .toList());
        snapshots.put(policy.version(), policy);
        this.current = policy;
    }

    public AccessPolicy current() {
        return current;
    }

    /** 按版本取历史快照；不存在返回 null。 */
    public AccessPolicy byVersion(String version) {
        return snapshots.get(version);
    }
}
