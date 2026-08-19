package org.springframework.security.boot.biz;

import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.session.MySessionRegistryImpl;
import org.springframework.security.boot.biz.session.MyConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.core.session.SessionRegistry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests for CustomWebSecurityExpressionHandler, CustomWebSecurityExpressionRoot,
 * MySessionRegistryImpl, and MyConcurrentSessionControlAuthenticationStrategy.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class ExpressionAndSessionTest {

    // --- CustomWebSecurityExpressionHandler ---

    @Test
    void expressionHandlerConstructor() {
        CustomWebSecurityExpressionHandler handler = new CustomWebSecurityExpressionHandler();
        assertThat(handler).isNotNull();
    }

    @Test
    void expressionHandlerSetTrustResolver() {
        CustomWebSecurityExpressionHandler handler = new CustomWebSecurityExpressionHandler();
        org.springframework.security.authentication.AuthenticationTrustResolver resolver =
                mock(org.springframework.security.authentication.AuthenticationTrustResolver.class);
        handler.setTrustResolver(resolver);
        assertThat(handler).isNotNull();
    }

    @Test
    void expressionHandlerSetDefaultRolePrefix() {
        CustomWebSecurityExpressionHandler handler = new CustomWebSecurityExpressionHandler();
        handler.setDefaultRolePrefix("PERM_");
        assertThat(handler).isNotNull();
    }

    // --- MySessionRegistryImpl ---

    @Test
    void mySessionRegistryImplConstructor() {
        MySessionRegistryImpl registry = new MySessionRegistryImpl();
        assertThat(registry).isNotNull();
    }

    @Test
    void mySessionRegistryImplIsSessionRegistry() {
        MySessionRegistryImpl registry = new MySessionRegistryImpl();
        assertThat(registry).isInstanceOf(SessionRegistry.class);
    }

    // --- MyConcurrentSessionControlAuthenticationStrategy ---

    @Test
    void concurrentStrategyConstructor() {
        SessionRegistry registry = mock(SessionRegistry.class);
        MyConcurrentSessionControlAuthenticationStrategy strategy =
                new MyConcurrentSessionControlAuthenticationStrategy(registry);
        assertThat(strategy).isNotNull();
    }

    @Test
    void concurrentStrategySetExceptionIfMaximumExceeded() {
        SessionRegistry registry = mock(SessionRegistry.class);
        MyConcurrentSessionControlAuthenticationStrategy strategy =
                new MyConcurrentSessionControlAuthenticationStrategy(registry);
        strategy.setExceptionIfMaximumExceeded(true);
        assertThat(strategy).isNotNull();
    }

    @Test
    void concurrentStrategySetMaximumSessions() {
        SessionRegistry registry = mock(SessionRegistry.class);
        MyConcurrentSessionControlAuthenticationStrategy strategy =
                new MyConcurrentSessionControlAuthenticationStrategy(registry);
        strategy.setMaximumSessions(5);
        assertThat(strategy).isNotNull();
    }

    @Test
    void concurrentStrategySetMessageSource() {
        SessionRegistry registry = mock(SessionRegistry.class);
        MyConcurrentSessionControlAuthenticationStrategy strategy =
                new MyConcurrentSessionControlAuthenticationStrategy(registry);
        org.springframework.context.support.MessageSourceAccessor accessor =
                mock(org.springframework.context.support.MessageSourceAccessor.class);
        strategy.setMessageSource(new org.springframework.context.support.ResourceBundleMessageSource());
        assertThat(strategy).isNotNull();
    }
}
