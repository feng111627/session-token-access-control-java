package com.github.feng111627.sessiontokenaccesscontroljava.access;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 鉴权策略：规则版本 + 规则列表 + 已知资源集合。
 * 配置格式："resource:action:ROLE1,ROLE2"，例如 "documents:read:USER,ADMIN"。
 */
public record AccessPolicy(String version, List<AccessRule> rules, Set<String> knownResources) {

    public static AccessPolicy parse(String version, List<String> ruleSpecs, List<String> resources) {
        List<AccessRule> rules = ruleSpecs.stream().map(spec -> {
            String[] parts = spec.split(":", -1);
            if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
                throw new IllegalArgumentException("invalid rule spec, expect resource:action:ROLE1,ROLE2 -> " + spec);
            }
            Set<String> roles = new LinkedHashSet<>();
            for (String r : parts[2].split(",")) {
                if (!r.isBlank()) roles.add(r.trim());
            }
            return new AccessRule(parts[0].trim(), parts[1].trim(), roles);
        }).toList();
        return new AccessPolicy(version, rules, new LinkedHashSet<>(resources));
    }
}
