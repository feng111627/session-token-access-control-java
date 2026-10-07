package com.github.feng111627.sessiontokenaccesscontroljava.authz;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/**
 * 一份不可变的鉴权策略快照。版本号由规则内容哈希得出：
 * 相同规则集永远得到相同版本号，因此同一请求在同一版本下的判定可复现，
 * 与重启、请求顺序无关。
 */
public record AccessPolicy(String version, List<PolicyRule> rules) {

    public static AccessPolicy of(List<PolicyRule> rules) {
        return new AccessPolicy(computeVersion(rules), List.copyOf(rules));
    }

    /** 按路径顺序匹配第一条命中的规则；无命中返回 null（默认拒绝）。 */
    public PolicyRule firstMatching(String path, String scope) {
        for (PolicyRule rule : rules) {
            if (rule.matchesPath(path) && rule.coversScope(scope)) return rule;
        }
        return null;
    }

    private static String computeVersion(List<PolicyRule> rules) {
        StringBuilder sb = new StringBuilder();
        for (PolicyRule r : rules) {
            sb.append(r.id()).append('|').append(r.pathPattern()).append('|')
              .append(String.join(",", r.roles().stream().sorted().toList())).append('|')
              .append(r.scope()).append('\n');
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(sb.toString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 8); // 16 位十六进制短版本号
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
