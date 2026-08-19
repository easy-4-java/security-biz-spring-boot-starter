package org.springframework.security.boot.biz.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests for PostRequestAuthenticationSuccessHandler, PostRequestAuthenticationFailureHandler,
 * PostRequestAuthenticationEntryPoint, PostRequestAuthenticationProvider, and related classes.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class AuthenticationHandlersTest {

    // --- PostRequestAuthenticationSuccessHandler ---

    @Test
    void successHandlerConstructorWithHandlers() {
        List<MatchedAuthenticationSuccessHandler> handlers = Collections.emptyList();
        PostRequestAuthenticationSuccessHandler handler = new PostRequestAuthenticationSuccessHandler(handlers);
        assertThat(handler.getSuccessHandlers()).isEmpty();
        assertThat(handler.isStateless()).isFalse();
    }

    @Test
    void successHandlerConstructorWithListenersAndHandlers() {
        List<AuthenticationListener> listeners = Collections.emptyList();
        List<MatchedAuthenticationSuccessHandler> handlers = Collections.emptyList();
        PostRequestAuthenticationSuccessHandler handler = new PostRequestAuthenticationSuccessHandler(listeners, handlers);
        assertThat(handler.getAuthenticationListeners()).isEmpty();
        assertThat(handler.getSuccessHandlers()).isEmpty();
    }

    @Test
    void successHandlerSettersAndGetters() {
        PostRequestAuthenticationSuccessHandler handler = new PostRequestAuthenticationSuccessHandler(Collections.emptyList());
        handler.setStateless(true);
        assertThat(handler.isStateless()).isTrue();
        handler.setMessages(null);
        assertThat(handler.getMessages()).isNull();
    }

    @Test
    void successHandlerOnAuthenticationSuccessPostRequest() throws Exception {
        PostRequestAuthenticationSuccessHandler handler = new PostRequestAuthenticationSuccessHandler(Collections.emptyList());
        handler.setStateless(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = mock(Authentication.class);
        handler.onAuthenticationSuccess(request, response, auth);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void successHandlerOnAuthenticationSuccessWithMatchingHandler() throws Exception {
        MatchedAuthenticationSuccessHandler matchedHandler = mock(MatchedAuthenticationSuccessHandler.class);
        when(matchedHandler.supports(any())).thenReturn(true);
        PostRequestAuthenticationSuccessHandler handler = new PostRequestAuthenticationSuccessHandler(List.of(matchedHandler));
        handler.setStateless(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = mock(Authentication.class);
        handler.onAuthenticationSuccess(request, response, auth);
        verify(matchedHandler).onAuthenticationSuccess(any(), any(), any());
    }

    @Test
    void successHandlerOnAuthenticationSuccessWithNonMatchingHandler() throws Exception {
        MatchedAuthenticationSuccessHandler matchedHandler = mock(MatchedAuthenticationSuccessHandler.class);
        when(matchedHandler.supports(any())).thenReturn(false);
        PostRequestAuthenticationSuccessHandler handler = new PostRequestAuthenticationSuccessHandler(List.of(matchedHandler));
        handler.setStateless(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = mock(Authentication.class);
        handler.onAuthenticationSuccess(request, response, auth);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void successHandlerOnAuthenticationSuccessWithListeners() throws Exception {
        AuthenticationListener listener = mock(AuthenticationListener.class);
        PostRequestAuthenticationSuccessHandler handler = new PostRequestAuthenticationSuccessHandler(
                List.of(listener), Collections.emptyList());
        handler.setStateless(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = mock(Authentication.class);
        handler.onAuthenticationSuccess(request, response, auth);
        verify(listener).onSuccess(any(), any(), any());
    }

    // --- PostRequestAuthenticationFailureHandler ---

    @Test
    void failureHandlerConstructorWithHandlers() {
        List<MatchedAuthenticationFailureHandler> handlers = Collections.emptyList();
        PostRequestAuthenticationFailureHandler handler = new PostRequestAuthenticationFailureHandler(handlers);
        assertThat(handler.getFailureHandlers()).isEmpty();
        assertThat(handler.isStateless()).isFalse();
    }

    @Test
    void failureHandlerConstructorWithListenersAndHandlers() {
        List<AuthenticationListener> listeners = Collections.emptyList();
        List<MatchedAuthenticationFailureHandler> handlers = Collections.emptyList();
        PostRequestAuthenticationFailureHandler handler = new PostRequestAuthenticationFailureHandler(listeners, handlers);
        assertThat(handler.getAuthenticationListeners()).isEmpty();
        assertThat(handler.getFailureHandlers()).isEmpty();
    }

    @Test
    void failureHandlerSettersAndGetters() {
        PostRequestAuthenticationFailureHandler handler = new PostRequestAuthenticationFailureHandler(Collections.emptyList());
        handler.setStateless(true);
        assertThat(handler.isStateless()).isTrue();
    }

    @Test
    void failureHandlerOnAuthenticationFailurePostRequest() throws Exception {
        PostRequestAuthenticationFailureHandler handler = new PostRequestAuthenticationFailureHandler(Collections.emptyList());
        handler.setStateless(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException ex = new BadCredentialsException("bad");
        handler.onAuthenticationFailure(request, response, ex);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void failureHandlerOnAuthenticationFailureWithMatchingHandler() throws Exception {
        MatchedAuthenticationFailureHandler matchedHandler = mock(MatchedAuthenticationFailureHandler.class);
        when(matchedHandler.supports(any())).thenReturn(true);
        PostRequestAuthenticationFailureHandler handler = new PostRequestAuthenticationFailureHandler(List.of(matchedHandler));
        handler.setStateless(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException ex = new BadCredentialsException("bad");
        handler.onAuthenticationFailure(request, response, ex);
        verify(matchedHandler).onAuthenticationFailure(any(), any(), any());
    }

    @Test
    void failureHandlerOnAuthenticationFailureWithNonMatchingHandler() throws Exception {
        MatchedAuthenticationFailureHandler matchedHandler = mock(MatchedAuthenticationFailureHandler.class);
        when(matchedHandler.supports(any())).thenReturn(false);
        PostRequestAuthenticationFailureHandler handler = new PostRequestAuthenticationFailureHandler(List.of(matchedHandler));
        handler.setStateless(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException ex = new BadCredentialsException("bad");
        handler.onAuthenticationFailure(request, response, ex);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void failureHandlerOnAuthenticationFailureWithListeners() throws Exception {
        AuthenticationListener listener = mock(AuthenticationListener.class);
        PostRequestAuthenticationFailureHandler handler = new PostRequestAuthenticationFailureHandler(
                List.of(listener), Collections.emptyList());
        handler.setStateless(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException ex = new BadCredentialsException("bad");
        handler.onAuthenticationFailure(request, response, ex);
        verify(listener).onFailure(any(), any(), any());
    }

    // --- PostRequestAuthenticationEntryPoint ---

    @Test
    void entryPointConstructor() {
        PostRequestAuthenticationEntryPoint entryPoint = new PostRequestAuthenticationEntryPoint("/login", Collections.emptyList());
        assertThat(entryPoint.getEntryPoints()).isEmpty();
        assertThat(entryPoint.isStateless()).isFalse();
    }

    @Test
    void entryPointSettersAndGetters() {
        PostRequestAuthenticationEntryPoint entryPoint = new PostRequestAuthenticationEntryPoint("/login", Collections.emptyList());
        entryPoint.setStateless(true);
        assertThat(entryPoint.isStateless()).isTrue();
        entryPoint.setEntryPoints(null);
        assertThat(entryPoint.getEntryPoints()).isNull();
    }

    @Test
    void entryPointCommencePostRequest() throws Exception {
        PostRequestAuthenticationEntryPoint entryPoint = new PostRequestAuthenticationEntryPoint("/login", Collections.emptyList());
        entryPoint.setStateless(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException ex = new BadCredentialsException("bad");
        entryPoint.commence(request, response, ex);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void entryPointCommenceWithMatchingEntryPoint() throws Exception {
        MatchedAuthenticationEntryPoint matchedEntryPoint = mock(MatchedAuthenticationEntryPoint.class);
        when(matchedEntryPoint.supports(any())).thenReturn(true);
        PostRequestAuthenticationEntryPoint entryPoint = new PostRequestAuthenticationEntryPoint("/login", List.of(matchedEntryPoint));
        entryPoint.setStateless(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException ex = new BadCredentialsException("bad");
        entryPoint.commence(request, response, ex);
        verify(matchedEntryPoint).commence(any(), any(), any());
    }

    @Test
    void entryPointCommenceWithNonMatchingEntryPoint() throws Exception {
        MatchedAuthenticationEntryPoint matchedEntryPoint = mock(MatchedAuthenticationEntryPoint.class);
        when(matchedEntryPoint.supports(any())).thenReturn(false);
        PostRequestAuthenticationEntryPoint entryPoint = new PostRequestAuthenticationEntryPoint("/login", List.of(matchedEntryPoint));
        entryPoint.setStateless(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException ex = new BadCredentialsException("bad");
        entryPoint.commence(request, response, ex);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    // --- PostRequestAuthenticationProvider ---

    @Test
    void providerSupports() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        org.springframework.security.crypto.password.PasswordEncoder passwordEncoder = mock(org.springframework.security.crypto.password.PasswordEncoder.class);
        PostRequestAuthenticationProvider provider = new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);
        assertThat(provider.supports(org.springframework.security.authentication.UsernamePasswordAuthenticationToken.class)).isTrue();
        assertThat(provider.supports(Authentication.class)).isFalse();
    }

    @Test
    void providerGetters() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        org.springframework.security.crypto.password.PasswordEncoder passwordEncoder = mock(org.springframework.security.crypto.password.PasswordEncoder.class);
        PostRequestAuthenticationProvider provider = new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);
        assertThat(provider.getUserDetailsService()).isEqualTo(userDetailsService);
        assertThat(provider.getPasswordEncoder()).isEqualTo(passwordEncoder);
        assertThat(provider.getUserDetailsChecker()).isNotNull();
    }

    @Test
    void providerSetUserDetailsChecker() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        org.springframework.security.crypto.password.PasswordEncoder passwordEncoder = mock(org.springframework.security.crypto.password.PasswordEncoder.class);
        PostRequestAuthenticationProvider provider = new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);
        org.springframework.security.core.userdetails.UserDetailsChecker checker = mock(org.springframework.security.core.userdetails.UserDetailsChecker.class);
        provider.setUserDetailsChecker(checker);
        assertThat(provider.getUserDetailsChecker()).isEqualTo(checker);
    }

    // --- NeteaseUrlAuthenticationSuccessHandler ---

    @Test
    void neteaseHandlerConstructor() {
        NeteaseUrlAuthenticationSuccessHandler handler = new NeteaseUrlAuthenticationSuccessHandler();
        assertThat(handler).isNotNull();
    }

    @Test
    void neteaseHandlerConstructorWithUrl() {
        NeteaseUrlAuthenticationSuccessHandler handler = new NeteaseUrlAuthenticationSuccessHandler("/home");
        assertThat(handler).isNotNull();
    }

    @Test
    void neteaseHandlerDetermineTargetUrlAlwaysDefault() {
        NeteaseUrlAuthenticationSuccessHandler handler = new NeteaseUrlAuthenticationSuccessHandler("/home");
        handler.setAlwaysUseDefaultTargetUrl(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String targetUrl = handler.determineTargetUrl(request, response);
        assertThat(targetUrl).isEqualTo("/home");
    }

    // --- AuthorizationPermissionEvaluator ---

    @Test
    void permissionEvaluatorWildcardPermission() {
        AuthorizationPermissionEvaluator evaluator = new AuthorizationPermissionEvaluator();
        Authentication auth = mock(Authentication.class);
        assertThat(evaluator.hasPermission(auth, null, "*")).isTrue();
    }

    @Test
    void permissionEvaluatorMatchingAuthority() {
        AuthorizationPermissionEvaluator evaluator = new AuthorizationPermissionEvaluator();
        Authentication auth = mock(Authentication.class);
        doReturn(List.of(new SimpleGrantedAuthority("READ"))).when(auth).getAuthorities();
        assertThat(evaluator.hasPermission(auth, null, "READ")).isTrue();
    }

    @Test
    void permissionEvaluatorNonMatchingAuthority() {
        AuthorizationPermissionEvaluator evaluator = new AuthorizationPermissionEvaluator();
        Authentication auth = mock(Authentication.class);
        doReturn(List.of(new SimpleGrantedAuthority("READ"))).when(auth).getAuthorities();
        assertThat(evaluator.hasPermission(auth, null, "WRITE")).isFalse();
    }

    @Test
    void permissionEvaluatorSerializableWildcard() {
        AuthorizationPermissionEvaluator evaluator = new AuthorizationPermissionEvaluator();
        Authentication auth = mock(Authentication.class);
        assertThat(evaluator.hasPermission(auth, "1", "type", "*")).isTrue();
    }

    @Test
    void permissionEvaluatorSerializableMatchingAuthority() {
        AuthorizationPermissionEvaluator evaluator = new AuthorizationPermissionEvaluator();
        Authentication auth = mock(Authentication.class);
        doReturn(List.of(new SimpleGrantedAuthority("ADMIN"))).when(auth).getAuthorities();
        assertThat(evaluator.hasPermission(auth, "1", "type", "ADMIN")).isTrue();
    }

    @Test
    void permissionEvaluatorSerializableNonMatchingAuthority() {
        AuthorizationPermissionEvaluator evaluator = new AuthorizationPermissionEvaluator();
        Authentication auth = mock(Authentication.class);
        doReturn(List.of(new SimpleGrantedAuthority("ADMIN"))).when(auth).getAuthorities();
        assertThat(evaluator.hasPermission(auth, "1", "type", "USER")).isFalse();
    }

    // --- AuthenticationListener ---

    @Test
    void authenticationListenerMockUsage() {
        AuthenticationListener listener = mock(AuthenticationListener.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = mock(Authentication.class);
        AuthenticationException ex = new BadCredentialsException("bad");
        listener.onSuccess(request, response, auth);
        listener.onFailure(request, response, ex);
        verify(listener).onSuccess(any(), any(), any());
        verify(listener).onFailure(any(), any(), any());
    }
}
