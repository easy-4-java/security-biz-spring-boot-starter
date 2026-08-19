package org.springframework.security.boot.biz;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;
import java.util.List;

/**
 * 认证请求失败后的处理实现
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class ListenedAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
	
	private List<AuthenticationListener> authenticationListeners;
	
	/**
	 * Constructs a new listened authentication failure handler instance.
	 *
	 * @param defaultFailureUrl the default failure url
	 */
	public ListenedAuthenticationFailureHandler(String defaultFailureUrl) {
		this.setDefaultFailureUrl(defaultFailureUrl);
	}
	
	/**
	 * Constructs a new listened authentication failure handler instance.
	 *
	 * @param authenticationListeners the authentication listeners
	 * @param defaultFailureUrl the default failure url
	 */
	public ListenedAuthenticationFailureHandler(List<AuthenticationListener> authenticationListeners, String defaultFailureUrl) {
		this.setAuthenticationListeners(authenticationListeners);
		this.setDefaultFailureUrl(defaultFailureUrl);
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

		//调用事件监听器
		if(getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0){
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onFailure(request, response, e);
			}
		}
		 
		super.onAuthenticationFailure(request, response, e);
		
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

}
