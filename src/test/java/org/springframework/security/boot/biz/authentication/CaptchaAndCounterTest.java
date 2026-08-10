package org.springframework.security.boot.biz.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.biz.authentication.captcha.NullCaptchaResolver;
import org.springframework.security.boot.biz.authentication.captcha.SessionCaptchaResolver;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for captcha resolvers and failure counters.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class CaptchaAndCounterTest {

    // NullCaptchaResolver
    @Test
    void nullCaptchaResolverAlwaysValid() {
        NullCaptchaResolver resolver = new NullCaptchaResolver();
        HttpServletRequest request = new MockHttpServletRequest();
        assertThat(resolver.validCaptcha(request, "any")).isTrue();
    }

    @Test
    void nullCaptchaResolverSetCaptchaDoesNothing() {
        NullCaptchaResolver resolver = new NullCaptchaResolver();
        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        resolver.setCaptcha(request, response, "text", new Date());
        // no exception thrown
    }

    // SessionCaptchaResolver
    @Test
    void sessionCaptchaResolverValidCaptchaWithEmptyText() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        HttpServletRequest request = new MockHttpServletRequest();
        assertThat(resolver.validCaptcha(request, "")).isFalse();
    }

    @Test
    void sessionCaptchaResolverValidCaptchaWithNullText() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        HttpServletRequest request = new MockHttpServletRequest();
        assertThat(resolver.validCaptcha(request, null)).isFalse();
    }

    @Test
    void sessionCaptchaResolverValidCaptchaWithNoSessionAttribute() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        HttpServletRequest request = new MockHttpServletRequest();
        assertThat(resolver.validCaptcha(request, "1234")).isFalse();
    }

    @Test
    void sessionCaptchaResolverValidCaptchaWithMatchingSessionAttribute() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(SessionCaptchaResolver.KAPTCHA_SESSION_ATTRIBUTE_NAME, "1234");
        assertThat(resolver.validCaptcha(request, "1234")).isTrue();
    }

    @Test
    void sessionCaptchaResolverValidCaptchaWithCaseInsensitiveMatch() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(SessionCaptchaResolver.KAPTCHA_SESSION_ATTRIBUTE_NAME, "ABCD");
        assertThat(resolver.validCaptcha(request, "abcd")).isTrue();
    }

    @Test
    void sessionCaptchaResolverValidCaptchaWithNonMatchingSessionAttribute() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(SessionCaptchaResolver.KAPTCHA_SESSION_ATTRIBUTE_NAME, "1234");
        assertThat(resolver.validCaptcha(request, "5678")).isFalse();
    }

    @Test
    void sessionCaptchaResolverSetCaptcha() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Date now = new Date();
        resolver.setCaptcha(request, response, "1234", now);
        assertThat(request.getSession().getAttribute(SessionCaptchaResolver.KAPTCHA_SESSION_ATTRIBUTE_NAME)).isEqualTo("1234");
        assertThat(request.getSession().getAttribute(SessionCaptchaResolver.KAPTCHA_DATE_SESSION_ATTRIBUTE_NAME)).isEqualTo(now);
    }

    @Test
    void sessionCaptchaResolverSetCaptchaWithNullText() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        resolver.setCaptcha(request, response, null, null);
        assertThat(request.getSession().getAttribute(SessionCaptchaResolver.KAPTCHA_SESSION_ATTRIBUTE_NAME)).isNull();
        assertThat(request.getSession().getAttribute(SessionCaptchaResolver.KAPTCHA_DATE_SESSION_ATTRIBUTE_NAME)).isNotNull();
    }

    @Test
    void sessionCaptchaResolverConstants() {
        assertThat(SessionCaptchaResolver.KAPTCHA_SESSION_ATTRIBUTE_NAME).contains("SessionCaptchaResolver");
        assertThat(SessionCaptchaResolver.KAPTCHA_DATE_SESSION_ATTRIBUTE_NAME).contains("SessionCaptchaResolver");
    }

    // AuthenticatingFailureRequestCounter
    @Test
    void authenticatingFailureRequestCounterDefaultParameter() {
        AuthenticatingFailureRequestCounter counter = new AuthenticatingFailureRequestCounter();
        assertThat(counter.getRetryTimesKeyParameter()).isEqualTo(AuthenticatingFailureCounter.DEFAULT_RETRY_TIMES_KEY_PARAM_NAME);
    }

    @Test
    void authenticatingFailureRequestCounterSetParameter() {
        AuthenticatingFailureRequestCounter counter = new AuthenticatingFailureRequestCounter();
        counter.setRetryTimesKeyParameter("customParam");
        assertThat(counter.getRetryTimesKeyParameter()).isEqualTo("customParam");
    }

    @Test
    void authenticatingFailureRequestCounterGetWithNoParameter() {
        AuthenticatingFailureRequestCounter counter = new AuthenticatingFailureRequestCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        int count = counter.get(request, null, "retryKey");
        assertThat(count).isEqualTo(0);
    }

    @Test
    void authenticatingFailureRequestCounterGetWithParameter() {
        AuthenticatingFailureRequestCounter counter = new AuthenticatingFailureRequestCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter(counter.getRetryTimesKeyParameter(), "3");
        int count = counter.get(request, null, "retryKey");
        assertThat(count).isEqualTo(3);
    }

    @Test
    void authenticatingFailureRequestCounterIncrementDoesNothing() {
        AuthenticatingFailureRequestCounter counter = new AuthenticatingFailureRequestCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        counter.increment(request, null, "retryKey");
        // no exception, no-op
    }

    // AuthenticatingFailureSessionCounter
    @Test
    void authenticatingFailureSessionCounterGetWithNoSessionAttribute() {
        AuthenticatingFailureSessionCounter counter = new AuthenticatingFailureSessionCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        int count = counter.get(request, null, "retryKey");
        assertThat(count).isEqualTo(0);
    }

    @Test
    void authenticatingFailureSessionCounterGetWithSessionAttribute() {
        AuthenticatingFailureSessionCounter counter = new AuthenticatingFailureSessionCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute("retryKey", "5");
        int count = counter.get(request, null, "retryKey");
        assertThat(count).isEqualTo(5);
    }

    @Test
    void authenticatingFailureSessionCounterIncrementFromZero() {
        AuthenticatingFailureSessionCounter counter = new AuthenticatingFailureSessionCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        counter.increment(request, null, "retryKey");
        assertThat(request.getSession().getAttribute("retryKey")).isEqualTo(1);
    }

    @Test
    void authenticatingFailureSessionCounterIncrementExisting() {
        AuthenticatingFailureSessionCounter counter = new AuthenticatingFailureSessionCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute("retryKey", 3L);
        counter.increment(request, null, "retryKey");
        assertThat(request.getSession().getAttribute("retryKey")).isEqualTo(4L);
    }

    // AuthenticatingFailureCounter interface constant
    @Test
    void authenticatingFailureCounterDefaultValue() {
        assertThat(AuthenticatingFailureCounter.DEFAULT_RETRY_TIMES_KEY_PARAM_NAME).isNotEmpty();
    }
}
