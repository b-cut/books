package com.aidanwhiteley.books.controller.config;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class SecurityConfigurationUrlPatterns {

    private static final List<RequestMatcher> PUBLIC_URLS = Arrays.asList(
            new AntPathRequestMatcher("/api/**"),
            new AntPathRequestMatcher("/login**"),
            new AntPathRequestMatcher("/feeds/**"),
            new AntPathRequestMatcher("/favicon.ico"),
            new AntPathRequestMatcher("/actuator/info"),
            new AntPathRequestMatcher("/actuator/health"),
            // And some paths just for playing with SWAGGER UI within the same app
            new AntPathRequestMatcher("/swagger-resources/**"),
            new AntPathRequestMatcher("/swagger-ui.html"),
            new AntPathRequestMatcher("/v2/api-docs"),
            new AntPathRequestMatcher("/webjars/**")
    );

    public static final List<RequestMatcher> PROTECTED_ACTUATOR_URLS = Collections.singletonList(
            new AntPathRequestMatcher("/actuator/**")
    );

    private static final RequestMatcher NON_OAUTH_PROTECTED_URLS = new OrRequestMatcher(
            Stream.concat(PUBLIC_URLS.stream(), PROTECTED_ACTUATOR_URLS.stream())
                    .collect(Collectors.toList())
    );

    public static final RequestMatcher OAUTH_PROTECTED_URLS = new NegatedRequestMatcher(NON_OAUTH_PROTECTED_URLS);
}
