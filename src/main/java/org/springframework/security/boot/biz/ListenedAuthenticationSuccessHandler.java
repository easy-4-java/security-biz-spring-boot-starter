package org.springframework.security.boot.biz;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;
import java.util.List;

/**
 * 认证请求成功后的处理实现
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class ListenedAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
	
	private List<AuthenticationListener> authenticationListeners;
	
	/**
	 * Constructs a new listened authentication success handler instance.
	 *
	 * @param defaultTargetUrl the default target url
	 */
	public ListenedAuthenticationSuccessHandler(String defaultTargetUrl) {
		this.setDefaultTargetUrl(defaultTargetUrl);
	}
	
	/**
	 * Constructs a new listened authentication success handler instance.
	 *
	 * @param authenticationListeners the authentication listeners
	 * @param defaultTargetUrl the default target url
	 */
	public ListenedAuthenticationSuccessHandler(List<AuthenticationListener> authenticationListeners, String defaultTargetUrl) {
		this.setAuthenticationListeners(authenticationListeners);
		this.setDefaultTargetUrl(defaultTargetUrl);
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
		
		//调用事件监听器
		if(getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0){
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onSuccess(request, response, authentication);
			}
		}
	 	 
		super.onAuthenticationSuccess(request, response, authentication);

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
