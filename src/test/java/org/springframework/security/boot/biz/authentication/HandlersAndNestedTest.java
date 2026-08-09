package org.springframework.security.boot.biz.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.biz.ListenedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.ListenedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.exception.*;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests for handlers, nested handlers, and authentication listeners.
 * @author [@Loong Wan](https://github.com/loong10k)
 */
class HandlersAndNestedTest {

    // DefaultMatchedAuthenticationEntryPoint
    @Test
    void defaultMatchedAuthenticationEntryPointSupports() {
        DefaultMatchedAuthenticationEntryPoint entryPoint = new DefaultMatchedAuthenticationEntryPoint();
        assertThat(entryPoint.supports(new AuthenticationMethodNotSupportedException("test"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationCaptchaNotFoundException("test"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationCaptchaIncorrectException("test"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationTokenNotFoundException("test"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationTokenIncorrectException("test"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationTokenExpiredException("test"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationCaptchaExpiredException("test"))).isFalse();
    }

    // DefaultMatchedAuthenticationFailureHandler
    @Test
    void defaultMatchedAuthenticationFailureHandlerSupports() {
        DefaultMatchedAuthenticationFailureHandler handler = new DefaultMatchedAuthenticationFailureHandler();
        assertThat(handler.supports(new AuthenticationMethodNotSupportedException("test"))).isTrue();
        assertThat(handler.supports(new AuthenticationCaptchaNotFoundException("test"))).isTrue();
        assertThat(handler.supports(new AuthenticationCaptchaIncorrectException("test"))).isTrue();
        assertThat(handler.supports(new AuthenticationTokenNotFoundException("test"))).isTrue();
        assertThat(handler.supports(new AuthenticationTokenIncorrectException("test"))).isTrue();
        assertThat(handler.supports(new AuthenticationTokenExpiredException("test"))).isTrue();
        assertThat(handler.supports(new AuthenticationCaptchaExpiredException("test"))).isFalse();
    }

    // ListenedAuthenticationSuccessHandler
    @Test
    void listenedAuthenticationSuccessHandlerConstructor() {
        ListenedAuthenticationSuccessHandler handler = new ListenedAuthenticationSuccessHandler("/");
        assertThat(handler).isNotNull();
        assertThat(handler.getAuthenticationListeners()).isNull();
    }

    @Test
    void listenedAuthenticationSuccessHandlerWithListeners() {
        List<AuthenticationListener> listeners = new ArrayList<>();
        listeners.add(mock(AuthenticationListener.class));
        ListenedAuthenticationSuccessHandler handler = new ListenedAuthenticationSuccessHandler(listeners, "/");
        assertThat(handler.getAuthenticationListeners()).hasSize(1);
    }

    @Test
    void listenedAuthenticationSuccessHandlerOnSuccess() throws Exception {
        AuthenticationListener listener = mock(AuthenticationListener.class);
        List<AuthenticationListener> listeners = new ArrayList<>();
        listeners.add(listener);
        ListenedAuthenticationSuccessHandler handler = new ListenedAuthenticationSuccessHandler(listeners, "/");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = mock(Authentication.class);
        handler.onAuthenticationSuccess(request, response, auth);
        verify(listener).onSuccess(request, response, auth);
    }

    @Test
    void listenedAuthenticationSuccessHandlerSetListeners() {
        ListenedAuthenticationSuccessHandler handler = new ListenedAuthenticationSuccessHandler("/");
        List<AuthenticationListener> listeners = new ArrayList<>();
        handler.setAuthenticationListeners(listeners);
        assertThat(handler.getAuthenticationListeners()).isEqualTo(listeners);
    }

    // ListenedAuthenticationFailureHandler
    @Test
    void listenedAuthenticationFailureHandlerConstructor() {
        ListenedAuthenticationFailureHandler handler = new ListenedAuthenticationFailureHandler("/");
        assertThat(handler).isNotNull();
        assertThat(handler.getAuthenticationListeners()).isNull();
    }

    @Test
    void listenedAuthenticationFailureHandlerWithListeners() {
        List<AuthenticationListener> listeners = new ArrayList<>();
        listeners.add(mock(AuthenticationListener.class));
        ListenedAuthenticationFailureHandler handler = new ListenedAuthenticationFailureHandler(listeners, "/");
        assertThat(handler.getAuthenticationListeners()).hasSize(1);
    }

    @Test
    void listenedAuthenticationFailureHandlerOnFailure() throws Exception {
        AuthenticationListener listener = mock(AuthenticationListener.class);
        List<AuthenticationListener> listeners = new ArrayList<>();
        listeners.add(listener);
        ListenedAuthenticationFailureHandler handler = new ListenedAuthenticationFailureHandler(listeners, "/");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException ex = new AuthenticationMethodNotSupportedException("test");
        handler.onAuthenticationFailure(request, response, ex);
        verify(listener).onFailure(request, response, ex);
    }

    @Test
    void listenedAuthenticationFailureHandlerSetListeners() {
        ListenedAuthenticationFailureHandler handler = new ListenedAuthenticationFailureHandler("/");
        List<AuthenticationListener> listeners = new ArrayList<>();
        handler.setAuthenticationListeners(listeners);
        assertThat(handler.getAuthenticationListeners()).isEqualTo(listeners);
    }

    // PostLoginRequest
    @Test
    void postLoginRequestNullCaptcha() {
        PostLoginRequest request = new PostLoginRequest("user", "pass", null);
        assertThat(request.getCaptcha()).isNull();
        request.setCaptcha("1234");
        assertThat(request.getCaptcha()).isEqualTo("1234");
    }

    // NeteaseUrlAuthenticationSuccessHandler
    @Test
    void neteaseUrlAuthenticationSuccessHandlerConstructor() {
        NeteaseUrlAuthenticationSuccessHandler handler = new NeteaseUrlAuthenticationSuccessHandler();
        assertThat(handler).isNotNull();
    }

    // AuthorizationPermissionEvaluator
    @Test
    void authorizationPermissionEvaluatorSupports() {
        AuthorizationPermissionEvaluator evaluator = new AuthorizationPermissionEvaluator();
        assertThat(evaluator).isNotNull();
    }

    // AuthenticatingFailureCounter constants
    @Test
    void authenticatingFailureCounterInterface() {
        assertThat(AuthenticatingFailureCounter.DEFAULT_RETRY_TIMES_KEY_PARAM_NAME).isNotEmpty();
    }
}
