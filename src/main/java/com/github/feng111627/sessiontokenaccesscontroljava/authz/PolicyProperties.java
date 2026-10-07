package com.github.feng111627.sessiontokenaccesscontroljava.authz;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * 鉴权规则的外部配置，绑定 {@code security.policy.rules} 前缀。
 * 修改配置即变更规则；规则内容决定策略版本号。
 */
@ConfigurationProperties(prefix = "security.policy")
public class PolicyProperties {

    public static class Rule {
        private String id;
        private String path;
        private Set<String> roles = Set.of();
        private String scope = "any";

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public Set<String> getRoles() { return roles; }
        public void setRoles(Set<String> roles) { this.roles = roles; }
        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = scope; }
    }

    private List<Rule> rules = new ArrayList<>();

    public List<Rule> getRules() { return rules; }
    public void setRules(List<Rule> rules) { this.rules = rules; }
}
