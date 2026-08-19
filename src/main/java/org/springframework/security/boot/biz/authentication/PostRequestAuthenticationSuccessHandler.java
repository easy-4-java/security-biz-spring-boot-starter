package org.springframework.security.boot.biz.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.utils.SecurityResponseUtils;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.util.List;

/**
 * Post认证请求成功后的处理实现
 * 
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class PostRequestAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private List<AuthenticationListener> authenticationListeners;
	private List<MatchedAuthenticationSuccessHandler> successHandlers;
	private boolean stateless = false;
	
	/**
	 * Constructs a new post request authentication success handler instance.
	 *
	 * @param successHandlers the success handlers
	 */
	public PostRequestAuthenticationSuccessHandler(List<MatchedAuthenticationSuccessHandler> successHandlers) {
		this.setSuccessHandlers(successHandlers);
	}

	/**
	 * Constructs a new post request authentication success handler instance.
	 *
	 * @param authenticationListeners the authentication listeners
	 * @param successHandlers the success handlers
	 */
	public PostRequestAuthenticationSuccessHandler(List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationSuccessHandler> successHandlers) {
		this.setAuthenticationListeners(authenticationListeners);
		this.setSuccessHandlers(successHandlers);
	}

	/**
	 * on Authentication Success.
	 *
	 * @param request the request
	 * @param response the response
	 * @param authentication the authentication
	 * @throws IOException if an error occurs
	 * @throws ServletException if an error occurs
	 */
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		// 调用事件监听器
		if (getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0) {
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onSuccess(request, response, authentication);
			}
		}

		/*
		 * if Rest request return json else rediect to specific page
		 */
		if ( isStateless() || WebUtils.isPostRequest(request)) {

			if (CollectionUtils.isEmpty(successHandlers)) {
				
				SecurityResponseUtils.handleSuccess(request, response, authentication);
				clearAuthenticationAttributes(request);
				
			} else {

				boolean isMatched = false;
				for (MatchedAuthenticationSuccessHandler successHandler : successHandlers) {

					if (successHandler != null && successHandler.supports(authentication)) {
						successHandler.onAuthenticationSuccess(request, response, authentication);
						isMatched = true;
						break;
					}

				}
				if (!isMatched) {
					SecurityResponseUtils.handleSuccess(request, response, authentication);
				}

				clearAuthenticationAttributes(request);

			}

		} else {
			super.onAuthenticationSuccess(request, response, authentication);
		}

	}

	/**
	 * Returns the authentication listeners.
	 *
	 * @return the authentication listeners
	 */
	public List<AuthenticationListener> getAuthenticationListeners() {
		return authenticationListeners;
	}

	/**
	 * Sets the authentication listeners.
	 *
	 * @param authenticationListeners the authentication listeners
	 */
	public void setAuthenticationListeners(List<AuthenticationListener> authenticationListeners) {
		this.authenticationListeners = authenticationListeners;
	}

	/**
	 * Returns the messages.
	 *
	 * @return the messages
	 */
	public MessageSourceAccessor getMessages() {
		return messages;
	}

	/**
	 * Returns the success handlers.
	 *
	 * @return the success handlers
	 */
	public List<MatchedAuthenticationSuccessHandler> getSuccessHandlers() {
		return successHandlers;
	}

	/**
	 * Sets the messages.
	 *
	 * @param messages the messages
	 */
	public void setMessages(MessageSourceAccessor messages) {
		this.messages = messages;
	}

	/**
	 * Sets the success handlers.
	 *
	 * @param successHandlers the success handlers
	 */
	public void setSuccessHandlers(List<MatchedAuthenticationSuccessHandler> successHandlers) {
		this.successHandlers = successHandlers;
	}

	/**
	 * Returns the stateless.
	 *
	 * @return the stateless
	 */
	public boolean isStateless() {
		return stateless;
	}

	/**
	 * Sets the stateless.
	 *
	 * @param stateless the stateless
	 */
	public void setStateless(boolean stateless) {
		this.stateless = stateless;
	}

}
