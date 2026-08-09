package org.springframework.security.boot.biz;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Tests for SecurityPrincipal, UserProfilePayload, IgnoreLogoutHandler, and related classes.
 * @author [@Loong Wan](https://github.com/loong10k)
 */
class UserDetailsAndHandlersTest {

    // SecurityPrincipal tests
    @Test
    void securityPrincipalConstructorWithRoles() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN", "ROLE_USER");
        assertThat(principal.getUsername()).isEqualTo("user");
        assertThat(principal.getPassword()).isEqualTo("pass");
        assertThat(principal.getAuthorities()).hasSize(2);
    }

    @Test
    void securityPrincipalConstructorWithAuthorities() {
        Collection<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", authorities);
        assertThat(principal.getUsername()).isEqualTo("user");
        assertThat(principal.getAuthorities()).hasSize(1);
    }

    @Test
    void securityPrincipalConstructorWithFullParams() {
        Collection<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", true, true, true, true, authorities);
        assertThat(principal.getUsername()).isEqualTo("user");
        assertThat(principal.isEnabled()).isTrue();
        assertThat(principal.isAccountNonExpired()).isTrue();
        assertThat(principal.isCredentialsNonExpired()).isTrue();
        assertThat(principal.isAccountNonLocked()).isTrue();
    }

    @Test
    void securityPrincipalRoleAuthoritiesWithNull() {
        assertThatThrownBy(() -> SecurityPrincipal.roleAuthorities(null))
                .isInstanceOf(InsufficientAuthenticationException.class);
    }

    @Test
    void securityPrincipalGettersAndSetters() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setUid("1");
        principal.setUuid("uuid-1");
        principal.setUkey("ukey-1");
        principal.setUcode("ucode-1");
        principal.setRid("10");
        principal.setRkey("rkey-10");
        principal.setRcode("rcode-10");
        principal.setBound(true);
        principal.setInitial(true);
        principal.setVerify(true);
        principal.setSign("sign-abc");
        principal.setAuthType("oauth2");
        principal.setLongitude(116.4);
        principal.setLatitude(39.9);

        assertThat(principal.getUid()).isEqualTo("1");
        assertThat(principal.getUuid()).isEqualTo("uuid-1");
        assertThat(principal.getUkey()).isEqualTo("ukey-1");
        assertThat(principal.getUcode()).isEqualTo("ucode-1");
        assertThat(principal.getRid()).isEqualTo("10");
        assertThat(principal.getRkey()).isEqualTo("rkey-10");
        assertThat(principal.getRcode()).isEqualTo("rcode-10");
        assertThat(principal.isBound()).isTrue();
        assertThat(principal.isInitial()).isTrue();
        assertThat(principal.isVerify()).isTrue();
        assertThat(principal.getSign()).isEqualTo("sign-abc");
        assertThat(principal.getAuthType()).isEqualTo("oauth2");
        assertThat(principal.getLongitude()).isEqualTo(116.4);
        assertThat(principal.getLatitude()).isEqualTo(39.9);
    }

    @Test
    void securityPrincipalPermsAndProfile() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Set<String> perms = new HashSet<>(Arrays.asList("read", "write"));
        principal.setPerms(perms);
        assertThat(principal.getPerms()).containsExactlyInAnyOrder("read", "write");

        Map<String, Object> profile = new HashMap<>();
        profile.put("email", "test@example.com");
        principal.setProfile(profile);
        assertThat(principal.getProfile()).containsEntry("email", "test@example.com");
    }

    @Test
    void securityPrincipalIsAdminWithNoRoles() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        assertThat(principal.isAdmin()).isFalse();
    }

    @Test
    void securityPrincipalHasRoleWithEmptyRole() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        assertThat(principal.hasRole("")).isFalse();
        assertThat(principal.hasRole(null)).isFalse();
    }

    @Test
    void securityPrincipalHasRoleWithNoRoles() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        assertThat(principal.hasRole("ADMIN")).isFalse();
    }

    @Test
    void securityPrincipalHasAnyRoleWithNoRoles() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        assertThat(principal.hasAnyRole("ADMIN")).isFalse();
    }

    @Test
    void securityPrincipalEqualsAndHashCode() {
        SecurityPrincipal p1 = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        p1.setUid("1");
        SecurityPrincipal p2 = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        p2.setUid("1");
        SecurityPrincipal p3 = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        p3.setUid("2");

        assertThat(p1).isEqualTo(p2);
        assertThat(p1.hashCode()).isEqualTo(p2.hashCode());
        assertThat(p1).isNotEqualTo(p3);
        assertThat(p1).isNotEqualTo(null);
        assertThat(p1).isNotEqualTo("string");
    }

    @Test
    void securityPrincipalToString() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setUid("1");
        String str = principal.toString();
        assertThat(str).contains("user");
        assertThat(str).contains("1");
    }

    @Test
    void securityPrincipalToPayload() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setUid("1");
        principal.setUuid("uuid-1");
        principal.setUkey("ukey-1");
        principal.setUcode("ucode-1");
        principal.setRid("10");
        principal.setRkey("rkey-10");
        principal.setRcode("rcode-10");
        principal.setBound(true);
        principal.setInitial(true);
        principal.setVerify(true);
        principal.setPerms(new HashSet<>(Arrays.asList("read")));
        principal.setProfile(new HashMap<>());

        UserProfilePayload payload = principal.toPayload();
        assertThat(payload.getUid()).isEqualTo("1");
        assertThat(payload.getUuid()).isEqualTo("uuid-1");
        assertThat(payload.getUkey()).isEqualTo("ukey-1");
        assertThat(payload.getUcode()).isEqualTo("ucode-1");
        assertThat(payload.getRid()).isEqualTo("10");
        assertThat(payload.getRkey()).isEqualTo("rkey-10");
        assertThat(payload.getRcode()).isEqualTo("rcode-10");
        assertThat(payload.isBound()).isTrue();
        assertThat(payload.isInitial()).isTrue();
        assertThat(payload.isVerify()).isTrue();
    }

    @Test
    void securityPrincipalToPayloadWithEmptyProfile() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setProfile(null);
        UserProfilePayload payload = principal.toPayload();
        assertThat(payload.getProfile()).isNotNull();
    }

    // UserProfilePayload tests
    @Test
    void userProfilePayloadGettersAndSetters() {
        UserProfilePayload payload = new UserProfilePayload();
        payload.setUid("1");
        payload.setUuid("uuid-1");
        payload.setUkey("ukey-1");
        payload.setUcode("ucode-1");
        payload.setRid("10");
        payload.setRkey("rkey-10");
        payload.setRcode("rcode-10");
        payload.setToken("jwt-token");
        payload.setBound(true);
        payload.setInitial(true);
        payload.setVerify(true);

        assertThat(payload.getUid()).isEqualTo("1");
        assertThat(payload.getUuid()).isEqualTo("uuid-1");
        assertThat(payload.getUkey()).isEqualTo("ukey-1");
        assertThat(payload.getUcode()).isEqualTo("ucode-1");
        assertThat(payload.getRid()).isEqualTo("10");
        assertThat(payload.getRkey()).isEqualTo("rkey-10");
        assertThat(payload.getRcode()).isEqualTo("rcode-10");
        assertThat(payload.getToken()).isEqualTo("jwt-token");
        assertThat(payload.isBound()).isTrue();
        assertThat(payload.isInitial()).isTrue();
        assertThat(payload.isVerify()).isTrue();
    }

    @Test
    void userProfilePayloadDefaultValues() {
        UserProfilePayload payload = new UserProfilePayload();
        assertThat(payload.isBound()).isFalse();
        assertThat(payload.isInitial()).isFalse();
        assertThat(payload.isVerify()).isFalse();
        assertThat(payload.getProfile()).isNotNull();
        assertThat(payload.getRoles()).isNotNull();
        assertThat(payload.getPerms()).isNotNull();
    }

    // IgnoreLogoutHandler tests
    @Test
    void ignoreLogoutHandlerDoesNothing() {
        IgnoreLogoutHandler handler = new IgnoreLogoutHandler();
        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = mock(Authentication.class);
        handler.logout(request, response, auth);
        // no exception thrown
    }
}
