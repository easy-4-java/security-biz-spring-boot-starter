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
package org.springframework.security.boot.biz.authentication.server;

import org.springframework.security.boot.biz.exception.*;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

/**
 * Default Matched Authentication Entry Point
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class DefaultMatchedServerAuthenticationEntryPoint implements MatchedServerAuthenticationEntryPoint {

	/**
	 * Determines whether supports.
	 *
	 * @param e the e
	 * @return the result
	 */
	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), AuthenticationMethodNotSupportedException.class,
				AuthenticationCaptchaNotFoundException.class, AuthenticationCaptchaIncorrectException.class,
				AuthenticationTokenNotFoundException.class, AuthenticationTokenIncorrectException.class,
				AuthenticationTokenExpiredException.class);
	}
	
}
