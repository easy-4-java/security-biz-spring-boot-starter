package org.springframework.security.boot.biz;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.biz.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.filter.CustomCorsFilter;
import org.springframework.security.boot.biz.filter.HttpParamsFilter;
import org.springframework.security.boot.biz.session.MyConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.boot.biz.session.MySessionRegistryImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests for token classes, filter classes, and session-related classes.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class TokensAndFiltersTest {

    // AbstractAuthenticationToken
    @Test
    void abstractAuthenticationTokenConstructor() {
        AbstractAuthenticationToken token = new AbstractAuthenticationToken("principal") {};
        assertThat(token.getPrincipal()).isEqualTo("principal");
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    void abstractAuthenticationTokenWithAuthorities() {
        Collection<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
        AbstractAuthenticationToken token = new AbstractAuthenticationToken("principal", "credentials", authorities) {};
        assertThat(token.getPrincipal()).isEqualTo("principal");
        assertThat(token.getCredentials()).isEqualTo("credentials");
        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getAuthorities()).hasSize(1);
    }

    @Test
    void abstractAuthenticationTokenSetAuthenticated() {
        AbstractAuthenticationToken token = new AbstractAuthenticationToken("principal") {};
        token.setAuthenticated(false);
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    void abstractAuthenticationTokenEraseCredentials() {
        Collection<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
        AbstractAuthenticationToken token = new AbstractAuthenticationToken("principal", "credentials", authorities) {};
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();
    }

    @Test
    void abstractAuthenticationTokenGettersAndSetters() {
        AbstractAuthenticationToken token = new AbstractAuthenticationToken("principal") {};
        token.setUid("1");
        token.setAppId("app-1");
        token.setAppChannel("web");
        token.setAppVersion("1.0");
        token.setSign("sign-abc");
        token.setLongitude(116.4);
        token.setLatitude(39.9);

        assertThat(token.getUid()).isEqualTo("1");
        assertThat(token.getAppId()).isEqualTo("app-1");
        assertThat(token.getAppChannel()).isEqualTo("web");
        assertThat(token.getAppVersion()).isEqualTo("1.0");
        assertThat(token.getSign()).isEqualTo("sign-abc");
        assertThat(token.getLongitude()).isEqualTo(116.4);
        assertThat(token.getLatitude()).isEqualTo(39.9);
    }

    // CustomCorsFilter
    @Test
    void customCorsFilterConstructor() {
        CustomCorsFilter filter = new CustomCorsFilter();
        assertThat(filter).isNotNull();
    }

    // HttpParamsFilter
    @Test
    void httpParamsFilterInitAndDestroy() throws ServletException {
        HttpParamsFilter filter = new HttpParamsFilter();
        filter.init(null);
        filter.destroy();
    }

    @Test
    void httpParamsFilterDoFilter() throws IOException, ServletException {
        HttpParamsFilter filter = new HttpParamsFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setPathInfo("/test");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        assertThat(request.getSession().getAttribute(HttpParamsFilter.REQUESTED_URL)).isEqualTo("/test");
    }

    @Test
    void httpParamsFilterConstant() {
        assertThat(HttpParamsFilter.REQUESTED_URL).isEqualTo("CasRequestedUrl");
    }

    // MySessionRegistryImpl
    @Test
    void mySessionRegistryImplConstructor() {
        MySessionRegistryImpl registry = new MySessionRegistryImpl();
        assertThat(registry).isNotNull();
    }

    // MyConcurrentSessionControlAuthenticationStrategy
    @Test
    void myConcurrentSessionControlAuthenticationStrategy() {
        SessionRegistry registry = mock(SessionRegistry.class);
        MyConcurrentSessionControlAuthenticationStrategy strategy =
                new MyConcurrentSessionControlAuthenticationStrategy(registry);
        assertThat(strategy).isNotNull();
    }

    // SpringSecurityBizMessageSource
    @Test
    void springSecurityBizMessageSourceAccessorNotNull() {
        var accessor = SpringSecurityBizMessageSource.getAccessor();
        assertThat(accessor).isNotNull();
    }
}
