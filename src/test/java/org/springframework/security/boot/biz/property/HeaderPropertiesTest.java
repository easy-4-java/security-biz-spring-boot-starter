package org.springframework.security.boot.biz.property;

import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.property.header.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for header property classes.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class HeaderPropertiesTest {

    @Test
    void headerHstsProperties() {
        HeaderHstsProperties props = new HeaderHstsProperties();
        assertThat(props).isNotNull();
    }

    @Test
    void headerFrameOptionsProperties() {
        HeaderFrameOptionsProperties props = new HeaderFrameOptionsProperties();
        assertThat(props).isNotNull();
    }

    @Test
    void headerContentSecurityPolicyProperties() {
        HeaderContentSecurityPolicyProperties props = new HeaderContentSecurityPolicyProperties();
        assertThat(props).isNotNull();
    }

    @Test
    void headerReferrerPolicyProperties() {
        HeaderReferrerPolicyProperties props = new HeaderReferrerPolicyProperties();
        assertThat(props).isNotNull();
    }

    @Test
    void headerHpkpProperties() {
        HeaderHpkpProperties props = new HeaderHpkpProperties();
        assertThat(props).isNotNull();
    }

    @Test
    void headerCacheControlProperties() {
        HeaderCacheControlProperties props = new HeaderCacheControlProperties();
        assertThat(props).isNotNull();
    }

    @Test
    void headerXssProtectionProperties() {
        HeaderXssProtectionProperties props = new HeaderXssProtectionProperties();
        assertThat(props).isNotNull();
    }

    @Test
    void headerContentTypeOptionsProperties() {
        HeaderContentTypeOptionsProperties props = new HeaderContentTypeOptionsProperties();
        assertThat(props).isNotNull();
    }

    @Test
    void headerFeaturePolicyProperties() {
        HeaderFeaturePolicyProperties props = new HeaderFeaturePolicyProperties();
        assertThat(props).isNotNull();
    }
}
