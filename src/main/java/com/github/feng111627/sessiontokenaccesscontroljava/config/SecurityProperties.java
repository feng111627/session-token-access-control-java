package com.github.feng111627.sessiontokenaccesscontroljava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * 可通过配置调整的安全参数与鉴权规则。
 */
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    private String tokenSecret = "dev-only-secret-change-me";
    private long accessTokenTtlMillis = 120_000;
    private long refreshTokenTtlMillis = 3_600_000;
    private int loginMaxFailures = 5;
    private long loginLockMillis = 300_000;
    private String ruleVersion = "v1";
    private List<String> rules = List.of();
    private List<String> resources = List.of();

    public String getTokenSecret() { return tokenSecret; }
    public void setTokenSecret(String tokenSecret) { this.tokenSecret = tokenSecret; }
    public long getAccessTokenTtlMillis() { return accessTokenTtlMillis; }
    public void setAccessTokenTtlMillis(long v) { this.accessTokenTtlMillis = v; }
    public long getRefreshTokenTtlMillis() { return refreshTokenTtlMillis; }
    public void setRefreshTokenTtlMillis(long v) { this.refreshTokenTtlMillis = v; }
    public int getLoginMaxFailures() { return loginMaxFailures; }
    public void setLoginMaxFailures(int v) { this.loginMaxFailures = v; }
    public long getLoginLockMillis() { return loginLockMillis; }
    public void setLoginLockMillis(long v) { this.loginLockMillis = v; }
    public String getRuleVersion() { return ruleVersion; }
    public void setRuleVersion(String ruleVersion) { this.ruleVersion = ruleVersion; }
    public List<String> getRules() { return rules; }
    public void setRules(List<String> rules) { this.rules = rules; }
    public List<String> getResources() { return resources; }
    public void setResources(List<String> resources) { this.resources = resources; }
}
