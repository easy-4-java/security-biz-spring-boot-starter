package org.springframework.security.boot.biz.exception;

import java.util.HashMap;
import java.util.Map;

/**
 * Auth response for interacting with client.
 * 
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class AuthResponse<T> {

	/**
	 * 成功或异常编码
	 */
	private final int code;
	/**
	 * 旧接口成功、失败或异常辅助判断标记:success、fail、error
	 */
	private final String status;
	/**
	 * 成功或异常消息
	 */
	private final String message;
	/**
	 * 成功或异常数据
	 */
	private T data;

	/**
	 * Constructs a new auth response instance.
	 *
	 * @param message the message
	 */
	public AuthResponse(final String message) {
		this.code = AuthResponseCode.SC_AUTHC_SUCCESS.getCode();
		this.status = AuthConstants.RT_SUCCESS;
		this.message = message;
	}

	/**
	 * Constructs a new auth response instance.
	 *
	 * @param code the code
	 */
	protected AuthResponse(final AuthResponseCode code) {
		this.code = code.getCode();
		;
		this.status = code.getStatus();
		this.message = null;
	}

	/**
	 * Constructs a new auth response instance.
	 *
	 * @param code the code
	 * @param data the data
	 */
	protected AuthResponse(final AuthResponseCode code, final T data) {
		this.code = code.getCode();
		;
		this.status = code.getStatus();
		this.message = null;
		this.data = data;
	}

	/**
	 * Constructs a new auth response instance.
	 *
	 * @param code the code
	 * @param message the message
	 * @param data the data
	 */
	protected AuthResponse(final AuthResponseCode code, final String message, final T data) {
		this.code = code.getCode();
		;
		this.status = code.getStatus();
		this.message = message;
		this.data = data;
	}

	/**
	 * Constructs a new auth response instance.
	 *
	 * @param code the code
	 * @param message the message
	 */
	protected AuthResponse(final int code, final String message) {
		this(code, AuthConstants.RT_SUCCESS, message);
	}

	/**
	 * Constructs a new auth response instance.
	 *
	 * @param code the code
	 * @param status the status
	 * @param message the message
	 */
	protected AuthResponse(final int code, final String status, final String message) {
		this.code = code;
		this.status = status;
		this.message = message;
	}

	/**
	 * Constructs a new auth response instance.
	 *
	 * @param code the code
	 * @param message the message
	 * @param data the data
	 */
	protected AuthResponse(final int code, final String message, final T data) {
		this(code, AuthConstants.RT_SUCCESS, message, data);
	}

	/**
	 * Constructs a new auth response instance.
	 *
	 * @param code the code
	 * @param status the status
	 * @param message the message
	 * @param data the data
	 */
	protected AuthResponse(final int code, final String status, final String message, final T data) {
		this.code = code;
		this.status = status;
		this.message = message;
		this.data = data;
	}

	// success -----------------------------------------------------------------

	/**
	 * success.
	 *
	 * @param message the message
	 * @return the result
	 */
	public static <T> AuthResponse<T> success(final String message) {
		return of(AuthResponseCode.SC_AUTHC_SUCCESS, message, null);
	}

	/**
	 * success.
	 *
	 * @param data the data
	 * @return the result
	 */
	public static <T> AuthResponse<T> success(final T data) {
		return of(AuthResponseCode.SC_AUTHC_SUCCESS, data);
	}

	/**
	 * success.
	 *
	 * @param message the message
	 * @param data the data
	 * @return the result
	 */
	public static <T> AuthResponse<T> success(final String message, final T data) {
		return of(AuthResponseCode.SC_AUTHC_SUCCESS, message, data);
	}

	/**
	 * success.
	 *
	 * @param code the code
	 * @param message the message
	 * @return the result
	 */
	public static <T> AuthResponse<T> success(final int code, final String message) {
		return of(code, AuthConstants.RT_SUCCESS, message);
	}

	// fail -----------------------------------------------------------------

	/**
	 * fail.
	 *
	 * @param message the message
	 * @return the result
	 */
	public static <T> AuthResponse<T> fail(final String message) {
		return of(AuthResponseCode.SC_AUTHC_FAIL, message, null);
	}

	/**
	 * fail.
	 *
	 * @param data the data
	 * @return the result
	 */
	public static <T> AuthResponse<T> fail(final T data) {
		return of(AuthResponseCode.SC_AUTHC_FAIL, data);
	}

	/**
	 * fail.
	 *
	 * @param code the code
	 * @param message the message
	 * @return the result
	 */
	public static <T> AuthResponse<T> fail(final int code, final String message) {
		return of(code, AuthConstants.RT_FAIL, message);
	}

	// -----------------------------------------------------------------

	/**
	 * of.
	 *
	 * @param code the code
	 * @return the result
	 */
	public static <T> AuthResponse<T> of(final AuthResponseCode code) {
		return new AuthResponse<T>(code);
	}

	/**
	 * of.
	 *
	 * @param code the code
	 * @param data the data
	 * @return the result
	 */
	public static <T> AuthResponse<T> of(final AuthResponseCode code, final T data) {
		return new AuthResponse<T>(code, data);
	}

	/**
	 * of.
	 *
	 * @param code the code
	 * @param message the message
	 * @param data the data
	 * @return the result
	 */
	public static <T> AuthResponse<T> of(final AuthResponseCode code, final String message, final T data) {
		return new AuthResponse<T>(code, message, data);
	}

	/**
	 * of.
	 *
	 * @param code the code
	 * @param message the message
	 * @return the result
	 */
	public static <T> AuthResponse<T> of(final String code, final String message) {
		return new AuthResponse<T>(Integer.parseInt(code), message);
	}

	/**
	 * of.
	 *
	 * @param code the code
	 * @param message the message
	 * @return the result
	 */
	public static <T> AuthResponse<T> of(final int code, final String message) {
		return new AuthResponse<T>(code, message);
	}

	/**
	 * of.
	 *
	 * @param code the code
	 * @param status the status
	 * @param message the message
	 * @return the result
	 */
	public static <T> AuthResponse<T> of(final String code, final String status, final String message) {
		return of(Integer.parseInt(code), status, message, null);
	}
	
	/**
	 * of.
	 *
	 * @param code the code
	 * @param status the status
	 * @param message the message
	 * @return the result
	 */
	public static <T> AuthResponse<T> of(final int code, final String status, final String message) {
		return of(code, status, message, null);
	}

	/**
	 * of.
	 *
	 * @param code the code
	 * @param status the status
	 * @param message the message
	 * @param data the data
	 * @return the result
	 */
	public static <T> AuthResponse<T> of(final int code, final String status, final String message, final T data) {
		return new AuthResponse<T>(code, status, message, data);
	}

	/**
	 * Returns the code.
	 *
	 * @return the code
	 */
	public int getCode() {
		return code;
	}

	/**
	 * Returns the status.
	 *
	 * @return the status
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * Returns the message.
	 *
	 * @return the message
	 */
	public String getmessage() {
		return message;
	}

	/**
	 * Returns the data.
	 *
	 * @return the data
	 */
	public T getData() {
		return data;
	}

	/**
	 * to Map.
	 *
	 * @return the result
	 */
	public Map<String, Object> toMap() {
		Map<String, Object> rtMap = new HashMap<String, Object>();
		rtMap.put("code", code);
		rtMap.put("status", status);
		rtMap.put("message", message);
		rtMap.put("data", data);
		return rtMap;
	}

}
