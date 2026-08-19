/*
 * Copyright (c) 2018, hiwepy (https://github.com/easy-4-java).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.utils;

import org.springframework.security.boot.biz.TrustedRedirectStrategy;
import org.springframework.security.boot.biz.authentication.*;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.ForwardAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.ForwardLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

import java.util.List;

/**
 * <p>Utility methods for Web Security.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class WebSecurityUtils {

	/**
	 * csrf Token Repository.
	 *
	 * @param sessionMgtProperties the session mgt properties
	 * @return the result
	 */
	public static CsrfTokenRepository csrfTokenRepository(SecuritySessionMgtProperties sessionMgtProperties) {
		// Session 管理器配置参数
		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgtProperties.getFixationPolicy())) {
			return CookieCsrfTokenRepository.withHttpOnlyFalse();
		}
		return new HttpSessionCsrfTokenRepository();
	}
	
	/**
	 * authentication Entry Point.
	 *
	 * @param authcProperties the authc properties
	 * @param sessionMgtProperties the session mgt properties
	 * @param entryPoints the entry points
	 * @return the result
	 */
	public static PostRequestAuthenticationEntryPoint authenticationEntryPoint(
			SecurityAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties,
			List<MatchedAuthenticationEntryPoint> entryPoints) {
		PostRequestAuthenticationEntryPoint entryPoint = new PostRequestAuthenticationEntryPoint(
				authcProperties.getPathPattern(), entryPoints);
		entryPoint.setForceHttps(authcProperties.getEntryPoint().isForceHttps());
		entryPoint.setStateless(SessionCreationPolicy.STATELESS.equals(sessionMgtProperties.getCreationPolicy()));
		entryPoint.setUseForward(authcProperties.getEntryPoint().isUseForward());
		return entryPoint;
	}
	
	/**
	 * authentication Failure Handler.
	 *
	 * @param authcProperties the authc properties
	 * @param sessionMgtProperties the session mgt properties
	 * @param authenticationListeners the authentication listeners
	 * @param failureHandlers the failure handlers
	 * @return the result
	 */
	public static PostRequestAuthenticationFailureHandler authenticationFailureHandler(
			SecurityAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties,
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationFailureHandler> failureHandlers) {

		PostRequestAuthenticationFailureHandler failureHandler = new PostRequestAuthenticationFailureHandler(
				authenticationListeners, failureHandlers);

		failureHandler.setAllowSessionCreation(sessionMgtProperties.isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(authcProperties.getFailureUrl());
		failureHandler.setRedirectStrategy(WebSecurityUtils.redirectStrategy(authcProperties));
		failureHandler.setStateless(SessionCreationPolicy.STATELESS.equals(sessionMgtProperties.getCreationPolicy()));
		failureHandler.setUseForward(authcProperties.isUseForward());

		return failureHandler;

	}
	
	/**
	 * authentication Success Handler.
	 *
	 * @param authcProperties the authc properties
	 * @param sessionMgtProperties the session mgt properties
	 * @param authenticationListeners the authentication listeners
	 * @param successHandlers the success handlers
	 * @return the result
	 */
	public static PostRequestAuthenticationSuccessHandler authenticationSuccessHandler(
			SecurityAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties,
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationSuccessHandler> successHandlers) {

		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, successHandlers);
		successHandler.setAlwaysUseDefaultTargetUrl(authcProperties.isAlwaysUseDefaultTargetUrl());
		successHandler.setDefaultTargetUrl(authcProperties.getSuccessUrl());
		successHandler.setRedirectStrategy(WebSecurityUtils.redirectStrategy(authcProperties));
		successHandler.setRequestCache(WebSecurityUtils.requestCache(authcProperties, sessionMgtProperties));
		successHandler.setStateless(SessionCreationPolicy.STATELESS.equals(sessionMgtProperties.getCreationPolicy()));
		successHandler.setTargetUrlParameter(authcProperties.getTargetUrlParameter());
		successHandler.setUseReferer(authcProperties.isUseReferer());

		return successHandler;
	}
	
	/**
	 * request Cache.
	 *
	 * @param authcProperties the authc properties
	 * @param sessionMgtProperties the session mgt properties
	 * @return the result
	 */
	public static RequestCache requestCache(SecurityAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties) {
 		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
 		requestCache.setCreateSessionAllowed(sessionMgtProperties.isAllowSessionCreation());
 		requestCache.setSessionAttrName(sessionMgtProperties.getSessionAttrName());
 		return requestCache;
 	}
	
	/**
	 * redirect Strategy.
	 *
	 * @param authcProperties the authc properties
	 * @return the result
	 */
	public static RedirectStrategy redirectStrategy(SecurityAuthcProperties authcProperties) {
		TrustedRedirectStrategy redirectStrategy = new TrustedRedirectStrategy();
		redirectStrategy.setContextRelative(authcProperties.getRedirect().isContextRelative());
		redirectStrategy.setDefaultRedirectUrl(authcProperties.getRedirect().getDefaultRedirectUrl());
		redirectStrategy.setTrustedRedirects(authcProperties.getRedirect().getTrustedRedirects());
		return redirectStrategy;
	}
	

	
	/**
	 * authenticating Failure Counter.
	 *
	 * @param authcProperties the authc properties
	 * @return the result
	 */
	public static AuthenticatingFailureCounter authenticatingFailureCounter(SecurityAuthcProperties authcProperties) {
		AuthenticatingFailureRequestCounter failureCounter = new AuthenticatingFailureRequestCounter();
		failureCounter.setRetryTimesKeyParameter(authcProperties.getRetry().getRetryTimesKeyParameter());
		return failureCounter;
	}

	
	/**
	 * authentication Failure Forward Handler.
	 *
	 * @param forwardUrl the forward url
	 * @return the result
	 */
	public static ForwardAuthenticationFailureHandler authenticationFailureForwardHandler(String forwardUrl) {
		return new ForwardAuthenticationFailureHandler(forwardUrl);
	}
	
	/**
	 * authentication Failure Simple URL Handler.
	 *
	 * @param authcProperties the authc properties
	 * @param sessionMgtProperties the session mgt properties
	 * @return the result
	 */
	public static SimpleUrlAuthenticationFailureHandler authenticationFailureSimpleUrlHandler(
			SecurityAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties ) {

		SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

		failureHandler.setAllowSessionCreation(sessionMgtProperties.isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(authcProperties.getFailureUrl());
		failureHandler.setRedirectStrategy(WebSecurityUtils.redirectStrategy(authcProperties));
		failureHandler.setUseForward(authcProperties.isUseForward());

		return failureHandler;
	}

	/**
	 * authentication Provider.
	 *
	 * @param userDetailsService the user details service
	 * @param passwordEncoder the password encoder
	 * @return the result
	 */
	public static PostRequestAuthenticationProvider authenticationProvider(UserDetailsServiceAdapter userDetailsService,
			PasswordEncoder passwordEncoder) {
		return new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);
	}
	
	/**
	 * logout Handler.
	 *
	 * @param logoutHandlers the logout handlers
	 * @return the result
	 */
	public static LogoutHandler logoutHandler(List<LogoutHandler> logoutHandlers) {
		return new CompositeLogoutHandler(logoutHandlers);
	}
	
	/**
	 * logout Success Forward Handler.
	 *
	 * @param targetUrl the target url
	 * @return the result
	 */
	public static LogoutSuccessHandler logoutSuccessForwardHandler(String targetUrl) {
		return new ForwardLogoutSuccessHandler(targetUrl);
	}

	
}
