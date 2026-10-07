package com.github.feng111627.sessiontokenaccesscontroljava.config;

import com.github.feng111627.sessiontokenaccesscontroljava.access.AccessPolicy;
import com.github.feng111627.sessiontokenaccesscontroljava.access.AuthorizationService;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.AuthService;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.LoginAttemptGuard;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.UserDirectory;
import com.github.feng111627.sessiontokenaccesscontroljava.token.AccessTokenService;
import com.github.feng111627.sessiontokenaccesscontroljava.token.RefreshTokenStore;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 装配内存用户库、令牌服务、限流守卫与鉴权服务。
 */
@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class AppConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public UserDirectory userDirectory() {
        return new UserDirectory();
    }

    @Bean
    public AccessTokenService accessTokenService(SecurityProperties props, Clock clock) {
        return new AccessTokenService(props.getTokenSecret(), props.getAccessTokenTtlMillis(), clock);
    }

    @Bean
    public RefreshTokenStore refreshTokenStore(SecurityProperties props, Clock clock) {
        return new RefreshTokenStore(props.getRefreshTokenTtlMillis(), clock);
    }

    @Bean
    public LoginAttemptGuard loginAttemptGuard(SecurityProperties props, Clock clock) {
        return new LoginAttemptGuard(props.getLoginMaxFailures(), props.getLoginLockMillis(), clock);
    }

    @Bean
    public AuthorizationService authorizationService(SecurityProperties props) {
        AccessPolicy policy = AccessPolicy.parse(props.getRuleVersion(), props.getRules(), props.getResources());
        return new AuthorizationService(policy);
    }

    @Bean
    public AuthService authService(UserDirectory users, LoginAttemptGuard guard,
                                   AccessTokenService accessTokens, RefreshTokenStore refreshTokens) {
        return new AuthService(users, guard, accessTokens, refreshTokens);
    }
}
