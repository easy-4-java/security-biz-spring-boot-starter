package org.springframework.security.boot.biz.exception;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AuthResponse}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class AuthResponseTest {

    @Test
    void successWithMessage() {
        AuthResponse<String> response = AuthResponse.success("OK");
        assertThat(response.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
        assertThat(response.getStatus()).isEqualTo(AuthConstants.RT_SUCCESS);
        assertThat(response.getmessage()).isEqualTo("OK");
        assertThat(response.getData()).isNull();
    }

    @Test
    void successWithData() {
        AuthResponse<String> response = AuthResponse.success("data-value");
        assertThat(response.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
        assertThat(response.getmessage()).isEqualTo("data-value");
    }

    @Test
    void successWithMessageAndData() {
        AuthResponse<String> response = AuthResponse.success("OK", "data-value");
        assertThat(response.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
        assertThat(response.getmessage()).isEqualTo("OK");
        assertThat(response.getData()).isEqualTo("data-value");
    }

    @Test
    void successWithCodeAndMessage() {
        AuthResponse<String> response = AuthResponse.success(200, "OK");
        assertThat(response.getCode()).isEqualTo(200);
        assertThat(response.getStatus()).isEqualTo(AuthConstants.RT_SUCCESS);
        assertThat(response.getmessage()).isEqualTo("OK");
    }

    @Test
    void failWithMessage() {
        AuthResponse<String> response = AuthResponse.fail("failed");
        assertThat(response.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_FAIL.getCode());
        assertThat(response.getStatus()).isEqualTo(AuthConstants.RT_ERROR);
        assertThat(response.getmessage()).isEqualTo("failed");
    }

    @Test
    void failWithData() {
        AuthResponse<String> response = AuthResponse.fail("error-data");
        assertThat(response.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_FAIL.getCode());
        assertThat(response.getmessage()).isEqualTo("error-data");
    }

    @Test
    void failWithCodeAndMessage() {
        AuthResponse<String> response = AuthResponse.fail(500, "server error");
        assertThat(response.getCode()).isEqualTo(500);
        assertThat(response.getStatus()).isEqualTo(AuthConstants.RT_FAIL);
        assertThat(response.getmessage()).isEqualTo("server error");
    }

    @Test
    void ofWithAuthResponseCode() {
        AuthResponse<Object> response = AuthResponse.of(AuthResponseCode.SC_AUTHC_SUCCESS);
        assertThat(response.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
        assertThat(response.getStatus()).isEqualTo(AuthResponseCode.SC_AUTHC_SUCCESS.getStatus());
    }

    @Test
    void ofWithAuthResponseCodeAndData() {
        AuthResponse<String> response = AuthResponse.of(AuthResponseCode.SC_AUTHC_SUCCESS, "test");
        assertThat(response.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
        assertThat(response.getData()).isEqualTo("test");
    }

    @Test
    void ofWithAuthResponseCodeMessageAndData() {
        AuthResponse<String> response = AuthResponse.of(AuthResponseCode.SC_AUTHC_SUCCESS, "msg", "data");
        assertThat(response.getCode()).isEqualTo(AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
        assertThat(response.getmessage()).isEqualTo("msg");
        assertThat(response.getData()).isEqualTo("data");
    }

    @Test
    void ofWithStringCodeAndMessage() {
        AuthResponse<String> response = AuthResponse.of("200", "OK");
        assertThat(response.getCode()).isEqualTo(200);
        assertThat(response.getmessage()).isEqualTo("OK");
    }

    @Test
    void ofWithIntCodeAndMessage() {
        AuthResponse<String> response = AuthResponse.of(200, "OK");
        assertThat(response.getCode()).isEqualTo(200);
        assertThat(response.getmessage()).isEqualTo("OK");
    }

    @Test
    void ofWithStringCodeStatusAndMessage() {
        AuthResponse<String> response = AuthResponse.of("200", "success", "OK");
        assertThat(response.getCode()).isEqualTo(200);
        assertThat(response.getStatus()).isEqualTo("success");
        assertThat(response.getmessage()).isEqualTo("OK");
    }

    @Test
    void ofWithIntCodeStatusAndMessage() {
        AuthResponse<String> response = AuthResponse.of(200, "success", "OK");
        assertThat(response.getCode()).isEqualTo(200);
        assertThat(response.getStatus()).isEqualTo("success");
        assertThat(response.getmessage()).isEqualTo("OK");
    }

    @Test
    void ofWithIntCodeStatusMessageAndData() {
        AuthResponse<String> response = AuthResponse.of(200, "success", "OK", "data");
        assertThat(response.getCode()).isEqualTo(200);
        assertThat(response.getStatus()).isEqualTo("success");
        assertThat(response.getmessage()).isEqualTo("OK");
        assertThat(response.getData()).isEqualTo("data");
    }

    @Test
    void toMap() {
        AuthResponse<String> response = AuthResponse.success("OK", "data");
        Map<String, Object> map = response.toMap();
        assertThat(map).containsKey("code");
        assertThat(map).containsKey("status");
        assertThat(map).containsKey("message");
        assertThat(map).containsKey("data");
        assertThat(map.get("code")).isEqualTo(AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
        assertThat(map.get("status")).isEqualTo(AuthConstants.RT_SUCCESS);
        assertThat(map.get("message")).isEqualTo("OK");
        assertThat(map.get("data")).isEqualTo("data");
    }
}
