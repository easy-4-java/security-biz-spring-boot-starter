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
 * Backward-compatible base class for the legacy feature security starters.
 * <p>
 * Extends {@link WebSecurityCustomizerAdapter} with authentication-specific
 * wiring (entry point, success/failure handlers, logout handler, request cache,
 * remember-me, session registry and session-authentication strategy) built from
 * the bound {@link SecurityAuthcProperties}.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public abstract class WebSecurityBizConfigurerAdapter extends WebSecurityCustomizerAdapter {

	/** Bound authentication properties (entry points, handlers, session, etc.). */
	private final SecurityAuthcProperties authcProperties;
	/** Optional explicit authentication manager; when {@code null} one is built from providers. */
	private final AuthenticationManager authenticationManager;

	/**
	 * Creates an adapter without an explicit authentication manager.
	 *
	 * @param bizProperties          business-level security properties
	 * @param sessionMgtProperties   session-management properties
	 * @param authenticationProviders authentication providers to register
	 */
	protected WebSecurityBizConfigurerAdapter(SecurityBizProperties bizProperties,
			SecuritySessionMgtProperties sessionMgtProperties,
			List<AuthenticationProvider> authenticationProviders) {
		super(bizProperties, sessionMgtProperties, authenticationProviders);
		this.authcProperties = null;
		this.authenticationManager = null;
	}

	/**
	 * Creates an adapter with explicit authentication properties and manager.
	 *
	 * @param bizProperties          business-level security properties
	 * @param authcProperties        authentication properties
	 * @param authenticationProviders authentication providers to register
	 * @param authenticationManager  explicit authentication manager (may be {@code null})
	 */
	protected WebSecurityBizConfigurerAdapter(SecurityBizProperties bizProperties,
			SecurityAuthcProperties authcProperties,
			List<? extends AuthenticationProvider> authenticationProviders,
			AuthenticationManager authenticationManager) {
		super(bizProperties, authcProperties.getSessionMgt(), new ArrayList<AuthenticationProvider>(authenticationProviders));
		this.authcProperties = authcProperties;
		this.authenticationManager = authenticationManager;
	}

	/**
	 * Returns the explicit authentication manager when set, otherwise falls
	 * back to the provider-based manager built by the superclass.
	 *
	 * @return the authentication manager to use
	 * @throws Exception if the manager cannot be built
	 */
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		if (Objects.nonNull(authenticationManager)) {
			return authenticationManager;
		}
		return super.authenticationManagerBean();
	}

	/**
	 * Builds the {@link AuthenticationEntryPoint} from the matched entry points.
	 *
	 * @param entryPoints the registered matched entry points
	 * @return a composite authentication entry point
	 */
	protected AuthenticationEntryPoint authenticationEntryPoint(List<MatchedAuthenticationEntryPoint> entryPoints) {
		return WebSecurityUtils.authenticationEntryPoint(authcProperties, sessionMgtProperties, entryPoints);
	}

	/**
	 * Builds the {@link AuthenticationSuccessHandler} from the listeners and matched handlers.
	 *
	 * @param authenticationListeners the registered authentication listeners
	 * @param successHandlers         the registered matched success handlers
	 * @return a composite authentication success handler
	 */
	protected AuthenticationSuccessHandler authenticationSuccessHandler(
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationSuccessHandler> successHandlers) {
		return WebSecurityUtils.authenticationSuccessHandler(authcProperties, sessionMgtProperties,
				authenticationListeners, successHandlers);
	}

	/**
	 * Builds the {@link AuthenticationFailureHandler} from the listeners and matched handlers.
	 *
	 * @param authenticationListeners the registered authentication listeners
	 * @param failureHandlers         the registered matched failure handlers
	 * @return a composite authentication failure handler
	 */
	protected AuthenticationFailureHandler authenticationFailureHandler(
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationFailureHandler> failureHandlers) {
		return WebSecurityUtils.authenticationFailureHandler(authcProperties, sessionMgtProperties,
				authenticationListeners, failureHandlers);
	}

	/**
	 * @return the invalid-session strategy ({@code null} by default; subclasses may override).
	 */
	protected InvalidSessionStrategy invalidSessionStrategy() {
		return null;
	}

	/**
	 * Builds a composite {@link LogoutHandler} from the given handlers.
	 *
	 * @param logoutHandlers the registered logout handlers
	 * @return a composite logout handler
	 */
	protected LogoutHandler logoutHandler(List<LogoutHandler> logoutHandlers) {
		return WebSecurityUtils.logoutHandler(logoutHandlers);
	}

	/**
	 * @return the {@link RequestCache} built from the authentication and session properties.
	 */
	protected RequestCache requestCache() {
		return WebSecurityUtils.requestCache(authcProperties, sessionMgtProperties);
	}

	/**
	 * @return a {@link NullRememberMeServices} (remember-me disabled) by default.
	 */
	protected RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
	}

	/**
	 * @return a {@link SessionRegistryImpl} tracking active HTTP sessions.
	 */
	protected SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	/**
	 * @return a {@link NullAuthenticatedSessionStrategy} by default.
	 */
	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
		return new NullAuthenticatedSessionStrategy();
	}

	/**
	 * @return the expired-session strategy ({@code null} by default; subclasses may override).
	 */
	protected SessionInformationExpiredStrategy sessionInformationExpiredStrategy() {
		return null;
	}

	/**
	 * Delegates to {@link #customize(WebSecurity)} to apply the web-security customisation.
	 *
	 * @param web the {@link WebSecurity} to configure
	 * @throws Exception if configuration fails
	 */
	public void configure(WebSecurity web) throws Exception {
		customize(web);
	}

}
