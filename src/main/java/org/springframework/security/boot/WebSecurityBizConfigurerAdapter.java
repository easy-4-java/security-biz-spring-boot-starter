/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.springframework.security.boot;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.utils.WebSecurityUtils;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Backward-compatible base class for legacy feature security starters.
 */
public abstract class WebSecurityBizConfigurerAdapter extends WebSecurityCustomizerAdapter {

	private final SecurityAuthcProperties authcProperties;
	private final AuthenticationManager authenticationManager;

	protected WebSecurityBizConfigurerAdapter(SecurityBizProperties bizProperties,
			SecuritySessionMgtProperties sessionMgtProperties,
			List<AuthenticationProvider> authenticationProviders) {
		super(bizProperties, sessionMgtProperties, authenticationProviders);
		this.authcProperties = null;
		this.authenticationManager = null;
	}

	protected WebSecurityBizConfigurerAdapter(SecurityBizProperties bizProperties,
			SecurityAuthcProperties authcProperties,
			List<? extends AuthenticationProvider> authenticationProviders,
			AuthenticationManager authenticationManager) {
		super(bizProperties, authcProperties.getSessionMgt(), new ArrayList<AuthenticationProvider>(authenticationProviders));
		this.authcProperties = authcProperties;
		this.authenticationManager = authenticationManager;
	}

	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		if (Objects.nonNull(authenticationManager)) {
			return authenticationManager;
		}
		return super.authenticationManagerBean();
	}

	protected AuthenticationEntryPoint authenticationEntryPoint(List<MatchedAuthenticationEntryPoint> entryPoints) {
		return WebSecurityUtils.authenticationEntryPoint(authcProperties, sessionMgtProperties, entryPoints);
	}

	protected AuthenticationSuccessHandler authenticationSuccessHandler(
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationSuccessHandler> successHandlers) {
		return WebSecurityUtils.authenticationSuccessHandler(authcProperties, sessionMgtProperties,
				authenticationListeners, successHandlers);
	}

	protected AuthenticationFailureHandler authenticationFailureHandler(
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationFailureHandler> failureHandlers) {
		return WebSecurityUtils.authenticationFailureHandler(authcProperties, sessionMgtProperties,
				authenticationListeners, failureHandlers);
	}

	protected InvalidSessionStrategy invalidSessionStrategy() {
		return null;
	}

	protected LogoutHandler logoutHandler(List<LogoutHandler> logoutHandlers) {
		return WebSecurityUtils.logoutHandler(logoutHandlers);
	}

	protected RequestCache requestCache() {
		return WebSecurityUtils.requestCache(authcProperties, sessionMgtProperties);
	}

	protected RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
	}

	protected SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
		return new NullAuthenticatedSessionStrategy();
	}

	protected SessionInformationExpiredStrategy sessionInformationExpiredStrategy() {
		return null;
	}

	public void configure(WebSecurity web) throws Exception {
		customize(web);
	}

}
