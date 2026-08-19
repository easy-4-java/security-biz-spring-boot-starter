package org.springframework.security.boot.biz.exception;

/**
 * Authentication Token Incorrect Exception
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class AuthenticationTokenIncorrectException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationTokenIncorrectException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationTokenIncorrectException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT, msg);
	}

	/**
	 * Constructs an <code>AuthenticationTokenIncorrectException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationTokenIncorrectException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT, msg, t);
	}
}
