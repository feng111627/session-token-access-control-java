package com.github.feng111627.sessiontokenaccesscontroljava.web;

import com.github.feng111627.sessiontokenaccesscontroljava.token.AccessTokenService;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 对受保护资源入口注册鉴权拦截器。
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final AccessTokenService accessTokenService;

    public WebConfig(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AuthInterceptor(accessTokenService)).addPathPatterns("/api/**");
    }
}
