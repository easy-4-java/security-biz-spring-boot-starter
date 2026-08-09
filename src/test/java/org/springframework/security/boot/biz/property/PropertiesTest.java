package org.springframework.security.boot.biz.property;

import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.property.header.*;
import org.springframework.security.config.http.SessionCreationPolicy;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for all Properties classes.
 * @author [@Loong Wan](https://github.com/loong10k)
 */
class PropertiesTest {

    // SecurityCaptchaProperties
    @Test
    void securityCaptchaProperties() {
        SecurityCaptchaProperties props = new SecurityCaptchaProperties();
        assertThat(props.getParamName()).isNotNull();
        assertThat(props.isRequired()).isFalse();
        props.setRequired(true);
        assertThat(props.isRequired()).isTrue();
    }

    // SecurityEntryPointProperties
    @Test
    void securityEntryPointProperties() {
        SecurityEntryPointProperties props = new SecurityEntryPointProperties();
        assertThat(props.isForceHttps()).isFalse();
        assertThat(props.isUseForward()).isFalse();
        props.setForceHttps(true);
        props.setUseForward(true);
        assertThat(props.isForceHttps()).isTrue();
        assertThat(props.isUseForward()).isTrue();
    }

    // SecurityFailureRetryProperties
    @Test
    void securityFailureRetryProperties() {
        SecurityFailureRetryProperties props = new SecurityFailureRetryProperties();
        assertThat(props.getRetryTimesKeyParameter()).isNotNull();
        assertThat(props.getRetryTimesKeyAttribute()).isNotNull();
        assertThat(props.getRetryTimesWhenAccessDenied()).isEqualTo(3);
        props.setRetryTimesWhenAccessDenied(5);
        assertThat(props.getRetryTimesWhenAccessDenied()).isEqualTo(5);
    }

    // SecurityHeaderCorsProperties
    @Test
    void securityHeaderCorsProperties() {
        SecurityHeaderCorsProperties props = new SecurityHeaderCorsProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.isAlwaysUseFullPath()).isFalse();
        assertThat(props.isUrlDecode()).isFalse();
        assertThat(props.isRemoveSemicolonContent()).isFalse();
        props.setEnabled(true);
        props.setAlwaysUseFullPath(true);
        props.setUrlDecode(true);
        props.setRemoveSemicolonContent(true);
        assertThat(props.isEnabled()).isTrue();
        assertThat(props.isAlwaysUseFullPath()).isTrue();
        assertThat(props.isUrlDecode()).isTrue();
        assertThat(props.isRemoveSemicolonContent()).isTrue();
    }

    // SecurityHeaderCsrfProperties
    @Test
    void securityHeaderCsrfProperties() {
        SecurityHeaderCsrfProperties props = new SecurityHeaderCsrfProperties();
        assertThat(props.isEnabled()).isFalse();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
    }

    // SecurityHeadersProperties
    @Test
    void securityHeadersProperties() {
        SecurityHeadersProperties props = new SecurityHeadersProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.getCacheControl()).isNotNull();
        assertThat(props.getContentSecurityPolicy()).isNotNull();
        assertThat(props.getContentTypeOptions()).isNotNull();
        assertThat(props.getFeaturePolicy()).isNotNull();
        assertThat(props.getFrameOptions()).isNotNull();
        assertThat(props.getHpkp()).isNotNull();
        assertThat(props.getHsts()).isNotNull();
        assertThat(props.getReferrerPolicy()).isNotNull();
        assertThat(props.getXssProtection()).isNotNull();
    }

    // SecurityLogoutProperties
    @Test
    void securityLogoutProperties() {
        SecurityLogoutProperties props = new SecurityLogoutProperties();
        assertThat(props.getPathPatterns()).isEqualTo("/logout");
        assertThat(props.isInvalidateHttpSession()).isTrue();
        assertThat(props.isClearAuthentication()).isTrue();
        props.setLogoutUrl("/custom-logout");
        props.setLogoutSuccessUrl("/goodbye");
        props.setInvalidateHttpSession(false);
        props.setClearAuthentication(false);
        assertThat(props.getLogoutUrl()).isEqualTo("/custom-logout");
        assertThat(props.getLogoutSuccessUrl()).isEqualTo("/goodbye");
        assertThat(props.isInvalidateHttpSession()).isFalse();
        assertThat(props.isClearAuthentication()).isFalse();
    }

    // SecurityRedirectProperties
    @Test
    void securityRedirectProperties() {
        SecurityRedirectProperties props = new SecurityRedirectProperties();
        assertThat(props.getDefaultRedirectUrl()).isEqualTo("/");
        assertThat(props.isContextRelative()).isFalse();
        assertThat(props.getTrustedRedirects()).isNotEmpty();
        props.setDefaultRedirectUrl("/home");
        props.setContextRelative(true);
        assertThat(props.getDefaultRedirectUrl()).isEqualTo("/home");
        assertThat(props.isContextRelative()).isTrue();
    }

    // SecurityRememberMeProperties
    @Test
    void securityRememberMeProperties() {
        SecurityRememberMeProperties props = new SecurityRememberMeProperties();
        assertThat(props.isContextRelative()).isFalse();
        props.setContextRelative(true);
        assertThat(props.isContextRelative()).isTrue();
    }

    // SecurityRequestProperties
    @Test
    void securityRequestProperties() {
        SecurityRequestProperties props = new SecurityRequestProperties();
        assertThat(props).isNotNull();
    }

    // SecuritySessionMgtProperties
    @Test
    void securitySessionMgtProperties() {
        SecuritySessionMgtProperties props = new SecuritySessionMgtProperties();
        assertThat(props.isAllowSessionCreation()).isTrue();
        assertThat(props.isEnableSessionUrlRewriting()).isFalse();
        assertThat(props.getFailureUrl()).isEqualTo("/error");
        assertThat(props.getMaximumSessions()).isEqualTo(1);
        assertThat(props.isMaxSessionsPreventsLogin()).isFalse();
        assertThat(props.getCreationPolicy()).isEqualTo(SessionCreationPolicy.STATELESS);
        assertThat(props.getFixationPolicy()).isEqualTo(SessionFixationPolicy.NONE);
        assertThat(props.getSessionAttrName()).isEqualTo("SPRING_SECURITY_SAVED_REQUEST");
        assertThat(props.getRemember()).isNotNull();
        assertThat(props.getLogout()).isNotNull();
        props.setAllowSessionCreation(false);
        props.setEnableSessionUrlRewriting(true);
        props.setFailureUrl("/custom-error");
        props.setMaximumSessions(5);
        props.setMaxSessionsPreventsLogin(true);
        props.setCreationPolicy(SessionCreationPolicy.ALWAYS);
        props.setFixationPolicy(SessionFixationPolicy.MIGRATE_SESSION);
        props.setSessionAttrName("CUSTOM_ATTR");
        assertThat(props.isAllowSessionCreation()).isFalse();
        assertThat(props.isEnableSessionUrlRewriting()).isTrue();
        assertThat(props.getFailureUrl()).isEqualTo("/custom-error");
        assertThat(props.getMaximumSessions()).isEqualTo(5);
        assertThat(props.isMaxSessionsPreventsLogin()).isTrue();
        assertThat(props.getCreationPolicy()).isEqualTo(SessionCreationPolicy.ALWAYS);
        assertThat(props.getFixationPolicy()).isEqualTo(SessionFixationPolicy.MIGRATE_SESSION);
        assertThat(props.getSessionAttrName()).isEqualTo("CUSTOM_ATTR");
    }

    // SessionFixationPolicy
    @Test
    void sessionFixationPolicy() {
        assertThat(SessionFixationPolicy.values()).hasSize(4);
        assertThat(SessionFixationPolicy.CHANGE_SESSION_ID.equals(SessionFixationPolicy.CHANGE_SESSION_ID)).isTrue();
        assertThat(SessionFixationPolicy.MIGRATE_SESSION.equals(SessionFixationPolicy.NEW_SESSION)).isFalse();
    }

    // Header properties
    @Test
    void headerCacheControlProperties() {
        HeaderCacheControlProperties props = new HeaderCacheControlProperties();
        assertThat(props.isEnabled()).isFalse();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
    }

    @Test
    void headerContentSecurityPolicyProperties() {
        HeaderContentSecurityPolicyProperties props = new HeaderContentSecurityPolicyProperties();
        assertThat(props.isEnabled()).isFalse();
        props.setPolicyDirectives("default-src 'self'");
        assertThat(props.getPolicyDirectives()).isEqualTo("default-src 'self'");
    }

    @Test
    void headerContentTypeOptionsProperties() {
        HeaderContentTypeOptionsProperties props = new HeaderContentTypeOptionsProperties();
        assertThat(props.isEnabled()).isFalse();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
    }

    @Test
    void headerFeaturePolicyProperties() {
        HeaderFeaturePolicyProperties props = new HeaderFeaturePolicyProperties();
        assertThat(props.isEnabled()).isFalse();
        props.setPolicyDirectives("geolocation 'self'");
        assertThat(props.getPolicyDirectives()).isEqualTo("geolocation 'self'");
    }

    @Test
    void headerFrameOptionsProperties() {
        HeaderFrameOptionsProperties props = new HeaderFrameOptionsProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.isDeny()).isFalse();
        assertThat(props.isSameOrigin()).isFalse();
        props.setSameOrigin(true);
        assertThat(props.isSameOrigin()).isTrue();
    }

    @Test
    void headerHpkpProperties() {
        HeaderHpkpProperties props = new HeaderHpkpProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.isReportOnly()).isTrue();
        assertThat(props.getSha256Pins()).isEmpty();
        props.setEnabled(true);
        props.setReportOnly(false);
        assertThat(props.isEnabled()).isTrue();
        assertThat(props.isReportOnly()).isFalse();
    }

    @Test
    void headerHstsProperties() {
        HeaderHstsProperties props = new HeaderHstsProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.isIncludeSubDomains()).isFalse();
        props.setEnabled(true);
        props.setIncludeSubDomains(true);
        assertThat(props.isEnabled()).isTrue();
        assertThat(props.isIncludeSubDomains()).isTrue();
    }

    @Test
    void headerReferrerPolicyProperties() {
        HeaderReferrerPolicyProperties props = new HeaderReferrerPolicyProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.getPolicy()).isNotNull();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
    }

    @Test
    void headerXssProtectionProperties() {
        HeaderXssProtectionProperties props = new HeaderXssProtectionProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.isBlock()).isFalse();
        props.setEnabled(true);
        props.setBlock(true);
        assertThat(props.isEnabled()).isTrue();
        assertThat(props.isBlock()).isTrue();
    }
}
