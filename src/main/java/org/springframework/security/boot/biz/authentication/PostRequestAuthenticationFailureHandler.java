package org.springframework.security.boot.biz.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.utils.SecurityResponseUtils;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.util.List;

/**
 * Post Request Authentication Failure Handler
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class PostRequestAuthenticationFailureHandler extends ExceptionMappingAuthenticationFailureHandler {

	protected Logger logger = LoggerFactory.getLogger(getClass());
	private List<AuthenticationListener> authenticationListeners;
	private List<MatchedAuthenticationFailureHandler> failureHandlers;
	private boolean stateless = false;
	
	/**
	 * Constructs a new post request authentication failure handler instance.
	 *
	 * @param failureHandlers the failure handlers
	 */
	public PostRequestAuthenticationFailureHandler(List<MatchedAuthenticationFailureHandler> failureHandlers) {
		this.setFailureHandlers(failureHandlers);
	}

	/**
	 * Constructs a new post request authentication failure handler instance.
	 *
	 * @param authenticationListeners the authentication listeners
	 * @param failureHandlers the failure handlers
	 */
	public PostRequestAuthenticationFailureHandler(List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationFailureHandler> failureHandlers) {
		this.setAuthenticationListeners(authenticationListeners);
		this.setFailureHandlers(failureHandlers);
	}

	/**
	 * on Authentication Failure.
	 *
	 * @param request the request
	 * @param response the response
	 * @param e the e
	 * @throws IOException if an error occurs
	 * @throws ServletException if an error occurs
	 */
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {

		// 调用事件监听器
		if (getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0) {
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onFailure(request, response, e);
			}
		}

		/*
		 * if Rest request return json else rediect to specific page
		 */
		if (isStateless() || WebUtils.isPostRequest(request)) {
			
			if(CollectionUtils.isEmpty(failureHandlers)) {
				SecurityResponseUtils.handleException(request, response, e);
			} else {
				
				boolean isMatched = false;
				for (MatchedAuthenticationFailureHandler failureHandler : failureHandlers) {
					
					if(failureHandler != null && failureHandler.supports(e)) {
						failureHandler.onAuthenticationFailure(request, response, e);
						isMatched = true;
						break;
					}
					
				}
				if(!isMatched) {
					SecurityResponseUtils.handleException(request, response, e);
				}
			}
			
		} else {
			super.onAuthenticationFailure(request, response, e);
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
	 * Returns the failure handlers.
	 *
	 * @return the failure handlers
	 */
	public List<MatchedAuthenticationFailureHandler> getFailureHandlers() {
		return failureHandlers;
	}

	/**
	 * Sets the failure handlers.
	 *
	 * @param failureHandlers the failure handlers
	 */
	public void setFailureHandlers(List<MatchedAuthenticationFailureHandler> failureHandlers) {
		this.failureHandlers = failureHandlers;
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