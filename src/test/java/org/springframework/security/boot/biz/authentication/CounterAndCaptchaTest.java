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
 * Tests for AuthenticatingFailureSessionCounter, AuthenticatingFailureRequestCounter,
 * NullCaptchaResolver, and SessionCaptchaResolver.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class CounterAndCaptchaTest {

    // --- AuthenticatingFailureSessionCounter ---

    @Test
    void sessionCounterGetReturnsZeroWhenNoAttribute() {
        AuthenticatingFailureSessionCounter counter = new AuthenticatingFailureSessionCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        int count = counter.get(request, response, "retryKey");
        assertThat(count).isEqualTo(0);
    }

    @Test
    void sessionCounterIncrementAndGet() {
        AuthenticatingFailureSessionCounter counter = new AuthenticatingFailureSessionCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        counter.increment(request, response, "retryKey");
        int count = counter.get(request, response, "retryKey");
        assertThat(count).isEqualTo(1);
    }

    @Test
    void sessionCounterIncrementMultipleTimes() {
        AuthenticatingFailureSessionCounter counter = new AuthenticatingFailureSessionCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        counter.increment(request, response, "retryKey");
        counter.increment(request, response, "retryKey");
        counter.increment(request, response, "retryKey");
        int count = counter.get(request, response, "retryKey");
        assertThat(count).isEqualTo(3);
    }

    // --- AuthenticatingFailureRequestCounter ---

    @Test
    void requestCounterGetReturnsZeroWhenNoParameter() {
        AuthenticatingFailureRequestCounter counter = new AuthenticatingFailureRequestCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        int count = counter.get(request, response, "retryKey");
        assertThat(count).isEqualTo(0);
    }

    @Test
    void requestCounterGetReturnsParameterValue() {
        AuthenticatingFailureRequestCounter counter = new AuthenticatingFailureRequestCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("failureRetries", "5");
        MockHttpServletResponse response = new MockHttpServletResponse();
        int count = counter.get(request, response, "retryKey");
        assertThat(count).isEqualTo(5);
    }

    @Test
    void requestCounterIncrementDoesNothing() {
        AuthenticatingFailureRequestCounter counter = new AuthenticatingFailureRequestCounter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        counter.increment(request, response, "retryKey");
        // increment is a no-op for request counter
    }

    @Test
    void requestCounterGettersAndSetters() {
        AuthenticatingFailureRequestCounter counter = new AuthenticatingFailureRequestCounter();
        assertThat(counter.getRetryTimesKeyParameter()).isEqualTo("failureRetries");
        counter.setRetryTimesKeyParameter("customKey");
        assertThat(counter.getRetryTimesKeyParameter()).isEqualTo("customKey");
    }

    // --- NullCaptchaResolver ---

    @Test
    void nullCaptchaResolverAlwaysValid() {
        NullCaptchaResolver resolver = new NullCaptchaResolver();
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThat(resolver.validCaptcha(request, "anything")).isTrue();
        assertThat(resolver.validCaptcha(request, null)).isTrue();
        assertThat(resolver.validCaptcha(request, "")).isTrue();
    }

    @Test
    void nullCaptchaResolverSetCaptchaDoesNothing() {
        NullCaptchaResolver resolver = new NullCaptchaResolver();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        resolver.setCaptcha(request, response, "captcha", new Date());
        // no exception thrown
    }

    // --- SessionCaptchaResolver ---

    @Test
    void sessionCaptchaResolverValidCaptchaWithEmptyText() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThat(resolver.validCaptcha(request, "")).isFalse();
        assertThat(resolver.validCaptcha(request, null)).isFalse();
    }

    @Test
    void sessionCaptchaResolverValidCaptchaWithNoSessionAttribute() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThat(resolver.validCaptcha(request, "1234")).isFalse();
    }

    @Test
    void sessionCaptchaResolverSetAndValidCaptcha() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        resolver.setCaptcha(request, response, "AbCd", new Date());
        assertThat(resolver.validCaptcha(request, "AbCd")).isTrue();
        assertThat(resolver.validCaptcha(request, "abcd")).isTrue();
        assertThat(resolver.validCaptcha(request, "wrong")).isFalse();
    }

    @Test
    void sessionCaptchaResolverSetCaptchaWithNullText() {
        SessionCaptchaResolver resolver = new SessionCaptchaResolver();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        resolver.setCaptcha(request, response, null, null);
        // no exception thrown
    }

    @Test
    void sessionCaptchaResolverConstants() {
        assertThat(SessionCaptchaResolver.KAPTCHA_SESSION_ATTRIBUTE_NAME).contains("SessionCaptchaResolver");
        assertThat(SessionCaptchaResolver.KAPTCHA_DATE_SESSION_ATTRIBUTE_NAME).contains("SessionCaptchaResolver");
    }

    // --- AuthenticatingFailureCounter interface ---

    @Test
    void authenticatingFailureCounterDefaultConstant() {
        assertThat(AuthenticatingFailureCounter.DEFAULT_RETRY_TIMES_KEY_PARAM_NAME).isEqualTo("failureRetries");
    }
}
