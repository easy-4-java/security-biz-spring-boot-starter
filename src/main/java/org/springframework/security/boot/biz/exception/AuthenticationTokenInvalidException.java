package org.springframework.security.boot.biz.exception;

/**
 * Authentication Token Invalid Exception
 * @author [@Loong Wan](https://github.com/loong10k)
 */
@SuppressWarnings("serial")
public class AuthenticationTokenInvalidException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationTokenInvalidException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationTokenInvalidException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_INVALID, msg);
	}

	/**
	 * Constructs an <code>AuthenticationTokenInvalidException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationTokenInvalidException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_INVALID, msg, t);
	}
}
