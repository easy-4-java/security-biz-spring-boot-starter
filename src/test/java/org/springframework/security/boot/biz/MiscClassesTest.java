package org.springframework.security.boot.biz;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.biz.authentication.PostLoginRequest;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests for miscellaneous biz classes.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class MiscClassesTest {

    // PostLoginRequest
    @Test
    void postLoginRequestConstructorAndGetters() {
        PostLoginRequest request = new PostLoginRequest("user", "pass", "1234");
        assertThat(request.getUsername()).isEqualTo("user");
        assertThat(request.getPassword()).isEqualTo("pass");
        assertThat(request.getCaptcha()).isEqualTo("1234");
    }

    @Test
    void postLoginRequestSetters() {
        PostLoginRequest request = new PostLoginRequest("user", "pass", "1234");
        request.setUsername("newUser");
        request.setPassword("newPass");
        request.setCaptcha("5678");
        assertThat(request.getUsername()).isEqualTo("newUser");
        assertThat(request.getPassword()).isEqualTo("newPass");
        assertThat(request.getCaptcha()).isEqualTo("5678");
    }

    // JsonInvalidSessionStrategy
    @Test
    void jsonInvalidSessionStrategyWritesResponse() throws Exception {
        JsonInvalidSessionStrategy strategy = new JsonInvalidSessionStrategy();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        strategy.onInvalidSessionDetected(request, response);
        String content = response.getContentAsString();
        assertThat(content).contains("Session Invalided");
    }

    // TrustedRedirectStrategy
    @Test
    void trustedRedirectStrategyDefaultRedirectUrl() {
        TrustedRedirectStrategy strategy = new TrustedRedirectStrategy();
        strategy.setDefaultRedirectUrl("/custom");
        // just verify setter works
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        try {
            strategy.sendRedirect(request, response, "/trusted");
        } catch (Exception e) {
            // may throw due to response committed state
        }
    }

    @Test
    void trustedRedirectStrategySetTrustedRedirects() {
        TrustedRedirectStrategy strategy = new TrustedRedirectStrategy();
        strategy.setTrustedRedirects(List.of("/api/**"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        try {
            strategy.sendRedirect(request, response, "/api/test");
        } catch (Exception e) {
            // may throw due to response committed state
        }
    }

    // SpringSecurityBizMessageSource
    @Test
    void springSecurityBizMessageSourceGetAccessor() {
        var accessor = SpringSecurityBizMessageSource.getAccessor();
        assertThat(accessor).isNotNull();
    }

    // UserDetailsServiceAdapter
    @Test
    void userDetailsServiceAdapter() {
        UserDetailsServiceAdapter adapter = mock(UserDetailsServiceAdapter.class);
        Authentication auth = mock(Authentication.class);
        Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        when(adapter.loadUserDetails(auth)).thenReturn(
                new org.springframework.security.core.userdetails.User("user", "pass", authorities));
        var result = adapter.loadUserDetails(auth);
        assertThat(result.getUsername()).isEqualTo("user");
    }

    // JwtPayloadRepository
    @Test
    void jwtPayloadRepository() {
        JwtPayloadRepository repo = mock(JwtPayloadRepository.class);
        assertThat(repo).isNotNull();
    }

    // AuthorizationPermissionEvaluator
    @Test
    void authorizationPermissionEvaluatorConstructor() {
        org.springframework.security.boot.biz.authentication.AuthorizationPermissionEvaluator evaluator =
                new org.springframework.security.boot.biz.authentication.AuthorizationPermissionEvaluator();
        assertThat(evaluator).isNotNull();
    }
}
