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
package org.springframework.security.boot.biz.authentication;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;

/**
 * Simple {@link PermissionEvaluator} that treats permission strings as
 * authority names: the current user has permission when one of their granted
 * authorities matches the requested permission (case-insensitive equality with
 * {@code "*"} grants access to everything).
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class AuthorizationPermissionEvaluator implements PermissionEvaluator {

	/** Wildcard permission value that matches any authority (matches all). */
	private static final String ALL = "*";

	/**
	 * Returns {@code true} when the authenticated user has an authority equal to
	 * the requested permission (or the permission is {@code "*"}).
	 *
	 * @param authentication      the current authentication
	 * @param targetDomainObject  ignored
	 * @param permission          the required permission / authority name
	 * @return {@code true} if access is granted
	 */
	@Override
	public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
		if (StringUtils.equalsIgnoreCase(ALL, permission.toString())) {
			return true;
		}
		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
		for (GrantedAuthority authority : authorities) {
			if (authority.getAuthority().equals(permission)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns {@code true} when the authenticated user has an authority equal to
	 * the requested permission (or the permission is {@code "*"}).
	 *
	 * @param authentication the current authentication
	 * @param targetId       ignored
	 * @param targetType     ignored
	 * @param permission     the required permission / authority name
	 * @return {@code true} if access is granted
	 */
	@Override
	public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
			Object permission) {
		if (StringUtils.equalsIgnoreCase(ALL, permission.toString())) {
			return true;
		}
		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
		for (GrantedAuthority authority : authorities) {
			if (authority.getAuthority().equals(permission)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns {@code true} when the current subject (resolved from the security
	 * context) has an authority equal to the requested permission (or the
	 * permission is {@code "*"}).
	 *
	 * @param permission the required permission / authority name
	 * @return {@code true} if access is granted
	 */
	public boolean hasPermission(Object permission) {
		if (StringUtils.equalsIgnoreCase(ALL, permission.toString())) {
			return true;
		}
		Collection<? extends GrantedAuthority> authorities = SubjectUtils.getAuthentication().getAuthorities();
		for (GrantedAuthority authority : authorities) {
			if (authority.getAuthority().equals(permission)) {
				return true;
			}
		}
		return false;
	}

}
