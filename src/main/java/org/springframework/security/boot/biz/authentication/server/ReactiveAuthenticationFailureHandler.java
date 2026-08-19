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

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.boot.utils.ReactiveSecurityResponseUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.util.CollectionUtils;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * <p>Handler for Reactive Authentication Failure.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class ReactiveAuthenticationFailureHandler implements ServerAuthenticationFailureHandler {

	private List<MatchedServerAuthenticationFailureHandler> failureHandlers;
	
	/**
	 * Constructs a new reactive authentication failure handler instance.
	 *
	 * @param failureHandlers the failure handlers
	 */
	public ReactiveAuthenticationFailureHandler(List<MatchedServerAuthenticationFailureHandler> failureHandlers) {
		this.setFailureHandlers(failureHandlers);
	}
	
    /**
     * on Authentication Failure.
     *
     * @param webFilterExchange the web filter exchange
     * @param e the e
     * @return the result
     */
    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException e) {
    	
    	// 1、获取ServerHttpResponse、ServerHttpResponse
    	ServerHttpRequest request = webFilterExchange.getExchange().getRequest();
		ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
		
        if(CollectionUtils.isEmpty(failureHandlers)) {
        	return ReactiveSecurityResponseUtils.handleFailure(request, response, e);
		} else {
			
			boolean isMatched = false;
			for (MatchedServerAuthenticationFailureHandler failureHandler : failureHandlers) {
				
				if(failureHandler != null && failureHandler.supports(e)) {
					failureHandler.onAuthenticationFailure(webFilterExchange, e);
					isMatched = true;
					break;
				}
				
			}
			if(!isMatched) {
				return ReactiveSecurityResponseUtils.handleFailure(request, response, e);
			}
		}
		return Mono.empty();
    }
    
	/**
	 * Returns the failure handlers.
	 *
	 * @return the failure handlers
	 */
	public List<MatchedServerAuthenticationFailureHandler> getFailureHandlers() {
		return failureHandlers;
	}

	/**
	 * Sets the failure handlers.
	 *
	 * @param failureHandlers the failure handlers
	 */
	public void setFailureHandlers(List<MatchedServerAuthenticationFailureHandler> failureHandlers) {
		this.failureHandlers = failureHandlers;
	}
    
}