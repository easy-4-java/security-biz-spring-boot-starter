package org.springframework.security.boot.biz.exception;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for exception classes and enums.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class ExceptionClassesTest {

    // AuthConstants tests
    @Test
    void authConstants() {
        assertThat(AuthConstants.UID).isEqualTo("uid");
        assertThat(AuthConstants.UKEY).isEqualTo("ukey");
        assertThat(AuthConstants.UCODE).isEqualTo("ucode");
        assertThat(AuthConstants.RID).isEqualTo("rid");
        assertThat(AuthConstants.RKEY).isEqualTo("rkey");
        assertThat(AuthConstants.RT_SUCCESS).isEqualTo("success");
        assertThat(AuthConstants.RT_FAIL).isEqualTo("fail");
        assertThat(AuthConstants.RT_ERROR).isEqualTo("error");
    }

    // ApiCodeValue tests
    @Test
    void apiCodeValues() {
        assertThat(ApiCodeValue.SC_SUCCESS).isEqualTo(200);
        assertThat(ApiCodeValue.SC_FAIL).isEqualTo(1000);
        assertThat(ApiCodeValue.SC_AUTHC_FAIL).isEqualTo(10001);
        assertThat(ApiCodeValue.SC_AUTHC_METHOD_NOT_ALLOWED).isEqualTo(10002);
        assertThat(ApiCodeValue.SC_AUTHC_OVER_RETRY_REMIND).isEqualTo(10003);
        assertThat(ApiCodeValue.SC_AUTHC_CAPTCHA_REQUIRED).isEqualTo(10004);
        assertThat(ApiCodeValue.SC_AUTHC_CAPTCHA_EXPIRED).isEqualTo(10005);
        assertThat(ApiCodeValue.SC_AUTHC_CAPTCHA_INCORRECT).isEqualTo(10006);
        assertThat(ApiCodeValue.SC_AUTHC_ACCOUNT_NOT_FOUND).isEqualTo(10007);
        assertThat(ApiCodeValue.SC_AUTHC_ACCOUNT_DISABLED).isEqualTo(10008);
        assertThat(ApiCodeValue.SC_AUTHC_ACCOUNT_EXPIRED).isEqualTo(10009);
        assertThat(ApiCodeValue.SC_AUTHC_ACCOUNT_LOCKED).isEqualTo(10010);
        assertThat(ApiCodeValue.SC_AUTHC_CREDENTIALS_EXPIRED).isEqualTo(10011);
        assertThat(ApiCodeValue.SC_AUTHC_BAD_CREDENTIALS).isEqualTo(10012);
        assertThat(ApiCodeValue.SC_AUTHZ_FAIL).isEqualTo(10020);
        assertThat(ApiCodeValue.SC_AUTHZ_TOKEN_ISSUED).isEqualTo(10021);
        assertThat(ApiCodeValue.SC_AUTHZ_TOKEN_REQUIRED).isEqualTo(10022);
        assertThat(ApiCodeValue.SC_AUTHZ_TOKEN_EXPIRED).isEqualTo(10023);
        assertThat(ApiCodeValue.SC_AUTHZ_TOKEN_INVALID).isEqualTo(10024);
        assertThat(ApiCodeValue.SC_AUTHZ_TOKEN_INCORRECT).isEqualTo(10025);
        assertThat(ApiCodeValue.SC_AUTHZ_CODE_REQUIRED).isEqualTo(10026);
        assertThat(ApiCodeValue.SC_AUTHZ_CODE_EXPIRED).isEqualTo(10027);
        assertThat(ApiCodeValue.SC_AUTHZ_CODE_INVALID).isEqualTo(10028);
        assertThat(ApiCodeValue.SC_AUTHZ_CODE_INCORRECT).isEqualTo(10029);
        assertThat(ApiCodeValue.SC_AUTHZ_THIRD_PARTY_SERVICE).isEqualTo(10030);
    }

    // AuthResponseCode tests
    @Test
    void authResponseCodeValues() {
        assertThat(AuthResponseCode.values()).isNotEmpty();
        assertThat(AuthResponseCode.valueOf("SC_AUTHC_SUCCESS")).isEqualTo(AuthResponseCode.SC_AUTHC_SUCCESS);
    }

    @Test
    void authResponseCodeProperties() {
        AuthResponseCode code = AuthResponseCode.SC_AUTHC_SUCCESS;
        assertThat(code.getCode()).isEqualTo(ApiCodeValue.SC_SUCCESS);
        assertThat(code.getStatus()).isEqualTo(AuthConstants.RT_SUCCESS);
        assertThat(code.getMsgKey()).isEqualTo("spring.security.authc.success");
    }

    @Test
    void authResponseCodeFail() {
        AuthResponseCode code = AuthResponseCode.SC_AUTHC_FAIL;
        assertThat(code.getCode()).isEqualTo(ApiCodeValue.SC_AUTHC_FAIL);
        assertThat(code.getStatus()).isEqualTo(AuthConstants.RT_ERROR);
    }

    // AuthenticationExceptionAdapter tests
    @Test
    void authenticationCaptchaExpiredException() {
        AuthenticationCaptchaExpiredException ex = new AuthenticationCaptchaExpiredException("expired");
        assertThat(ex.getMessage()).isEqualTo("expired");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_CAPTCHA_EXPIRED.getCode());
        assertThat(ex.getMsgKey()).isEqualTo(AuthResponseCode.SC_AUTHC_CAPTCHA_EXPIRED.getMsgKey());
    }

    @Test
    void authenticationCaptchaExpiredExceptionWithCause() {
        Throwable cause = new RuntimeException("root");
        AuthenticationCaptchaExpiredException ex = new AuthenticationCaptchaExpiredException("expired", cause);
        assertThat(ex.getMessage()).isEqualTo("expired");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void authenticationCaptchaIncorrectException() {
        AuthenticationCaptchaIncorrectException ex = new AuthenticationCaptchaIncorrectException("incorrect");
        assertThat(ex.getMessage()).isEqualTo("incorrect");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_CAPTCHA_INCORRECT.getCode());
    }

    @Test
    void authenticationCaptchaIncorrectExceptionWithCause() {
        Throwable cause = new RuntimeException("root");
        AuthenticationCaptchaIncorrectException ex = new AuthenticationCaptchaIncorrectException("incorrect", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void authenticationCaptchaNotFoundException() {
        AuthenticationCaptchaNotFoundException ex = new AuthenticationCaptchaNotFoundException("not found");
        assertThat(ex.getMessage()).isEqualTo("not found");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_CAPTCHA_REQUIRED.getCode());
    }

    @Test
    void authenticationCaptchaNotFoundExceptionWithCause() {
        Throwable cause = new RuntimeException("root");
        AuthenticationCaptchaNotFoundException ex = new AuthenticationCaptchaNotFoundException("not found", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void authenticationMethodNotSupportedException() {
        AuthenticationMethodNotSupportedException ex = new AuthenticationMethodNotSupportedException("not supported");
        assertThat(ex.getMessage()).isEqualTo("not supported");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getCode());
    }

    @Test
    void authenticationMethodNotSupportedExceptionWithCause() {
        Throwable cause = new RuntimeException("root");
        AuthenticationMethodNotSupportedException ex = new AuthenticationMethodNotSupportedException("not supported", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void authenticationOverRetryRemindException() {
        AuthenticationOverRetryRemindException ex = new AuthenticationOverRetryRemindException("over retry");
        assertThat(ex.getMessage()).isEqualTo("over retry");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_OVER_RETRY_REMIND.getCode());
    }

    @Test
    void authenticationOverRetryRemindExceptionWithCause() {
        Throwable cause = new RuntimeException("root");
        AuthenticationOverRetryRemindException ex = new AuthenticationOverRetryRemindException("over retry", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void authenticationServiceExceptionAdapter() {
        AuthenticationMethodNotSupportedException ex = new AuthenticationMethodNotSupportedException("service error");
        assertThat(ex.getMessage()).isEqualTo("service error");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getCode());
    }

    @Test
    void authenticationServiceExceptionAdapterWithCause() {
        Throwable cause = new RuntimeException("root");
        AuthenticationMethodNotSupportedException ex = new AuthenticationMethodNotSupportedException("service error", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void authenticationTokenExpiredException() {
        AuthenticationTokenExpiredException ex = new AuthenticationTokenExpiredException("expired");
        assertThat(ex.getMessage()).isEqualTo("expired");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getCode());
    }

    @Test
    void authenticationTokenExpiredExceptionWithCause() {
        Throwable cause = new RuntimeException("root");
        AuthenticationTokenExpiredException ex = new AuthenticationTokenExpiredException("expired", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void authenticationTokenIncorrectException() {
        AuthenticationTokenIncorrectException ex = new AuthenticationTokenIncorrectException("incorrect");
        assertThat(ex.getMessage()).isEqualTo("incorrect");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getCode());
    }

    @Test
    void authenticationTokenIncorrectExceptionWithCause() {
        Throwable cause = new RuntimeException("root");
        AuthenticationTokenIncorrectException ex = new AuthenticationTokenIncorrectException("incorrect", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void authenticationTokenInvalidException() {
        AuthenticationTokenInvalidException ex = new AuthenticationTokenInvalidException("invalid");
        assertThat(ex.getMessage()).isEqualTo("invalid");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_TOKEN_INVALID.getCode());
    }

    @Test
    void authenticationTokenInvalidExceptionWithCause() {
        Throwable cause = new RuntimeException("root");
        AuthenticationTokenInvalidException ex = new AuthenticationTokenInvalidException("invalid", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    void authenticationTokenNotFoundException() {
        AuthenticationTokenNotFoundException ex = new AuthenticationTokenNotFoundException("not found");
        assertThat(ex.getMessage()).isEqualTo("not found");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_TOKEN_REQUIRED.getCode());
    }

    @Test
    void authenticationTokenNotFoundExceptionWithCause() {
        Throwable cause = new RuntimeException("root");
        AuthenticationTokenNotFoundException ex = new AuthenticationTokenNotFoundException("not found", cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }
}
