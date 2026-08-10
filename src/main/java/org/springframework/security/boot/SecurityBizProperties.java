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
package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Business-level configuration properties for the Spring Security Biz starter.
 * <p>
 * Bound to the {@code spring.security.*} namespace. Currently exposes a
 * Shiro-style filter-chain definition map used to seed the default security
 * filter rules (URL pattern &rarr; chain name).</p>
 *
 * <h3>Configuration</h3>
 * <ul>
 *   <li>{@code spring.security.filter-chain-definition-map} &mdash; ordered map
 *       of URL pattern to filter-chain name used to initialise the default
 *       filter rules (default empty)</li>
 * </ul>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConfigurationProperties(SecurityBizProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityBizProperties {

	/** Configuration prefix for the security business properties. */
	public static final String PREFIX = "spring.security";

	/**
	 * Shiro-style filter-chain definition map (URL pattern &rarr; chain name)
	 * used to initialise the default security filter rules.
	 */
	private Map<String, String > filterChainDefinitionMap = new LinkedHashMap<>(16);

}
