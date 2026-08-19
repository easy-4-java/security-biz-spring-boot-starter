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

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequest;

/**
 * TODO
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

public class WebfluxUtils {

	private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
    private static final String X_REQUESTED_WITH = "X-Requested-With";
    private static final String CONTENT_TYPE_JSON = "application/json";

	/**
	 * Determines whether is ajax response.
	 *
	 * @param request the request
	 * @return the result
	 */
	public static boolean isAjaxResponse(ServerHttpRequest request ) {
		return isAjaxRequest(request) || isContentTypeJson(request) || isPostRequest(request);
	}

    /**
     * Determines whether is object request.
     *
     * @param request the request
     * @return the result
     */
    public static boolean isObjectRequest(ServerHttpRequest request ) {
        return isPostRequest(request) && isContentTypeJson(request);
    }

    /**
     * Determines whether is object request.
     *
     * @param request the request
     * @return the result
     */
    public static boolean isObjectRequest(HttpRequest request ) {
        return isPostRequest(request) && isContentTypeJson(request);
    }
    
    /**
     * Determines whether is ajax request.
     *
     * @param request the request
     * @return the result
     */
    public static boolean isAjaxRequest(ServerHttpRequest request ) {
        return XML_HTTP_REQUEST.equals(request.getHeaders().getFirst(X_REQUESTED_WITH));
    }
    
    /**
     * Determines whether is ajax request.
     *
     * @param request the request
     * @return the result
     */
    public static boolean isAjaxRequest(HttpRequest request ) {
        return request.getHeaders().get(X_REQUESTED_WITH).contains(XML_HTTP_REQUEST);
    }

    /**
     * Determines whether is content type json.
     *
     * @param request the request
     * @return the result
     */
    public static boolean isContentTypeJson(ServerHttpRequest request ) {
        return request.getHeaders().get(HttpHeaders.CONTENT_TYPE).contains(CONTENT_TYPE_JSON);
    }
    
    /**
     * Determines whether is content type json.
     *
     * @param request the request
     * @return the result
     */
    public static boolean isContentTypeJson(HttpRequest request ) {
        return request.getHeaders().get(HttpHeaders.CONTENT_TYPE).contains(CONTENT_TYPE_JSON);
    }
    
    /**
     * Determines whether is post request.
     *
     * @param request the request
     * @return the result
     */
    public static boolean isPostRequest(ServerHttpRequest request ) {
        return HttpMethod.POST.compareTo(request.getMethod()) == 0;
    }
    
    /**
     * Determines whether is post request.
     *
     * @param request the request
     * @return the result
     */
    public static boolean isPostRequest(HttpRequest request ) {
        return HttpMethod.POST.compareTo(request.getMethod()) == 0;
    }
    
}
