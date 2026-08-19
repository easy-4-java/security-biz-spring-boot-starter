package org.springframework.security.boot.biz.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * <p>Adapter for Authentication Exception.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public abstract class AuthenticationExceptionAdapter extends AuthenticationException {

	private final int code;
	private final String msgKey;

	/**
	 * Constructs a new authentication exception adapter instance.
	 *
	 * @param code the code
	 * @param msg the msg
	 */
	public AuthenticationExceptionAdapter(AuthResponseCode code, String msg) {
		super(msg);
		this.code = code.getCode();
		this.msgKey = code.getMsgKey();
	}
	
	/**
	 * Constructs a new authentication exception adapter instance.
	 *
	 * @param code the code
	 * @param msg the msg
	 * @param t the t
	 */
	public AuthenticationExceptionAdapter(AuthResponseCode code, String msg, Throwable t) {
		super(msg, t);
		this.code = code.getCode();
		this.msgKey = code.getMsgKey();
	}

	/**
	 * Constructs a new authentication exception adapter instance.
	 *
	 * @param code the code
	 * @param msg the msg
	 * @param t the t
	 */
	public AuthenticationExceptionAdapter(int code, String msg, Throwable t) {
		super(msg, t);
		this.code = code;
		this.msgKey = null;
	}

	/**
	 * Constructs a new authentication exception adapter instance.
	 *
	 * @param code the code
	 * @param msgKey the msg key
	 * @param msg the msg
	 * @param t the t
	 */
	public AuthenticationExceptionAdapter(int code, String msgKey, String msg, Throwable t) {
		super(msg, t);
		this.code = code;
		this.msgKey = msgKey;
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
	 * Returns the msg key.
	 *
	 * @return the msg key
	 */
	public String getMsgKey() {
		return msgKey;
	}

}
