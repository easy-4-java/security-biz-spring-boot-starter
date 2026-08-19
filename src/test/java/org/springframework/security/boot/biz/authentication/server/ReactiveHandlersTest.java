package org.springframework.security.boot.biz.authentication.server;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.exception.AuthenticationMethodNotSupportedException;
import org.springframework.security.boot.biz.exception.AuthenticationCaptchaNotFoundException;
import org.springframework.security.boot.biz.exception.AuthenticationTokenNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests for reactive authentication handlers and server-side classes.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class ReactiveHandlersTest {

    // --- ReactiveAuthenticationSuccessHandler ---

    @Test
    void reactiveSuccessHandlerConstructor() {
        ReactiveAuthenticationSuccessHandler handler = new ReactiveAuthenticationSuccessHandler(Collections.emptyList());
        assertThat(handler.getSuccessHandlers()).isEmpty();
    }

    @Test
    void reactiveSuccessHandlerSettersAndGetters() {
        ReactiveAuthenticationSuccessHandler handler = new ReactiveAuthenticationSuccessHandler(Collections.emptyList());
        List<MatchedServerAuthenticationSuccessHandler> handlers = List.of(mock(MatchedServerAuthenticationSuccessHandler.class));
        handler.setSuccessHandlers(handlers);
        assertThat(handler.getSuccessHandlers()).hasSize(1);
    }

    // --- ReactiveAuthenticationFailureHandler ---

    @Test
    void reactiveFailureHandlerConstructor() {
        ReactiveAuthenticationFailureHandler handler = new ReactiveAuthenticationFailureHandler(Collections.emptyList());
        assertThat(handler.getFailureHandlers()).isEmpty();
    }

    @Test
    void reactiveFailureHandlerSettersAndGetters() {
        ReactiveAuthenticationFailureHandler handler = new ReactiveAuthenticationFailureHandler(Collections.emptyList());
        List<MatchedServerAuthenticationFailureHandler> handlers = List.of(mock(MatchedServerAuthenticationFailureHandler.class));
        handler.setFailureHandlers(handlers);
        assertThat(handler.getFailureHandlers()).hasSize(1);
    }

    // --- ReactiveAuthenticationEntryPoint ---

    @Test
    void reactiveEntryPointConstructor() {
        ReactiveAuthenticationEntryPoint entryPoint = new ReactiveAuthenticationEntryPoint(Collections.emptyList());
        assertThat(entryPoint.getEntryPoints()).isEmpty();
    }

    @Test
    void reactiveEntryPointSettersAndGetters() {
        ReactiveAuthenticationEntryPoint entryPoint = new ReactiveAuthenticationEntryPoint(Collections.emptyList());
        entryPoint.setMessages(null);
        assertThat(entryPoint.getMessages()).isNull();
        List<MatchedServerAuthenticationEntryPoint> entryPoints = List.of(mock(MatchedServerAuthenticationEntryPoint.class));
        entryPoint.setEntryPoints(entryPoints);
        assertThat(entryPoint.getEntryPoints()).hasSize(1);
    }

    // --- DefaultMatchedServerAuthenticationEntryPoint ---

    @Test
    void defaultMatchedEntryPointSupportsMethodNotSupported() {
        DefaultMatchedServerAuthenticationEntryPoint entryPoint = new DefaultMatchedServerAuthenticationEntryPoint();
        AuthenticationException ex = new AuthenticationMethodNotSupportedException("not supported");
        assertThat(entryPoint.supports(ex)).isTrue();
    }

    @Test
    void defaultMatchedEntryPointSupportsCaptchaNotFound() {
        DefaultMatchedServerAuthenticationEntryPoint entryPoint = new DefaultMatchedServerAuthenticationEntryPoint();
        AuthenticationException ex = new AuthenticationCaptchaNotFoundException("captcha not found");
        assertThat(entryPoint.supports(ex)).isTrue();
    }

    @Test
    void defaultMatchedEntryPointSupportsTokenNotFound() {
        DefaultMatchedServerAuthenticationEntryPoint entryPoint = new DefaultMatchedServerAuthenticationEntryPoint();
        AuthenticationException ex = new AuthenticationTokenNotFoundException("token not found");
        assertThat(entryPoint.supports(ex)).isTrue();
    }

    @Test
    void defaultMatchedEntryPointDoesNotSupportGeneric() {
        DefaultMatchedServerAuthenticationEntryPoint entryPoint = new DefaultMatchedServerAuthenticationEntryPoint();
        AuthenticationException ex = new BadCredentialsException("bad");
        assertThat(entryPoint.supports(ex)).isFalse();
    }

    // --- DefaultMatchedServerAuthenticationFailureHandler ---

    @Test
    void defaultMatchedFailureHandlerSupportsMethodNotSupported() {
        DefaultMatchedServerAuthenticationFailureHandler handler = new DefaultMatchedServerAuthenticationFailureHandler();
        AuthenticationException ex = new AuthenticationMethodNotSupportedException("not supported");
        assertThat(handler.supports(ex)).isTrue();
    }

    @Test
    void defaultMatchedFailureHandlerSupportsCaptchaNotFound() {
        DefaultMatchedServerAuthenticationFailureHandler handler = new DefaultMatchedServerAuthenticationFailureHandler();
        AuthenticationException ex = new AuthenticationCaptchaNotFoundException("captcha not found");
        assertThat(handler.supports(ex)).isTrue();
    }

    @Test
    void defaultMatchedFailureHandlerDoesNotSupportGeneric() {
        DefaultMatchedServerAuthenticationFailureHandler handler = new DefaultMatchedServerAuthenticationFailureHandler();
        AuthenticationException ex = new BadCredentialsException("bad");
        assertThat(handler.supports(ex)).isFalse();
    }

    // --- JwtAuthenticationWebFilter ---

    @Test
    void jwtAuthenticationWebFilterConstructor() {
        org.springframework.security.authentication.ReactiveAuthenticationManager manager =
                mock(org.springframework.security.authentication.ReactiveAuthenticationManager.class);
        JwtAuthenticationWebFilter filter = new JwtAuthenticationWebFilter(manager);
        assertThat(filter).isNotNull();
    }

    // --- MatchedServerAuthenticationSuccessHandler interface ---

    @Test
    void matchedServerAuthenticationSuccessHandlerInterface() {
        assertThat(MatchedServerAuthenticationSuccessHandler.class.isInterface()).isTrue();
    }

    // --- MatchedServerAuthenticationFailureHandler interface ---

    @Test
    void matchedServerAuthenticationFailureHandlerInterface() {
        assertThat(MatchedServerAuthenticationFailureHandler.class.isInterface()).isTrue();
    }

    // --- MatchedServerAuthenticationEntryPoint interface ---

    @Test
    void matchedServerAuthenticationEntryPointInterface() {
        assertThat(MatchedServerAuthenticationEntryPoint.class.isInterface()).isTrue();
    }
}
