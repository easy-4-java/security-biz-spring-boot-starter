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

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * <p>Token for Abstract Authentication.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class AbstractAuthenticationToken extends org.springframework.security.authentication.AbstractAuthenticationToken {
    
    private final Object principal;
    private Object credentials;
    /**
	 * 登录的用户UID
	 */
	private String uid;
	/**
	 * 登录的客户端应用ID
	 */
	private String appId;
	/**
	 * 登录的客户端应用渠道编码
	 */
	private String appChannel;
	/**
	 *登录的客户端版本
	 */
	private String appVersion;
	/**
	 * 请求参数签名（可选）
	 */
	private String sign;
	/**
	 * 用户最新经度（可选）
	 */
	private double longitude;
	/**
	 * 用户最新纬度（可选）
	 */
	private double latitude;

	    /**
	     * Constructs a new abstract authentication token instance.
	     *
	     * @param principal the principal
	     */
	    public AbstractAuthenticationToken(Object principal) {
	        super((Collection<? extends GrantedAuthority>) null);
        this.principal = principal;
        setAuthenticated(false);
    }
    
    /**
     * Constructs a new abstract authentication token instance.
     *
     * @param principal the principal
     * @param credentials the credentials
     * @param authorities the authorities
     */
    public AbstractAuthenticationToken( Object principal,  Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true); // must use super, as we override
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * Returns the credentials.
     *
     * @return the credentials
     */
    public Object getCredentials() {
        return this.credentials;
    }

    /**
     * Returns the principal.
     *
     * @return the principal
     */
    public Object getPrincipal() {
        return this.principal;
    }

    /**
     * Sets the authenticated.
     *
     * @param isAuthenticated the is authenticated
     * @throws IllegalArgumentException if an error occurs
     */
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }

    /**
     * erase Credentials.
     *
     */
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
    }
    
	/**
	 * Returns the uid.
	 *
	 * @return the uid
	 */
	public String getUid() {
		return uid;
	}

	/**
	 * Sets the uid.
	 *
	 * @param uid the uid
	 */
	public void setUid(String uid) {
		this.uid = uid;
	}

	/**
	 * Returns the app id.
	 *
	 * @return the app id
	 */
	public String getAppId() {
		return appId;
	}

	/**
	 * Sets the app id.
	 *
	 * @param appId the app id
	 */
	public void setAppId(String appId) {
		this.appId = appId;
	}

	/**
	 * Returns the app channel.
	 *
	 * @return the app channel
	 */
	public String getAppChannel() {
		return appChannel;
	}

	/**
	 * Sets the app channel.
	 *
	 * @param appChannel the app channel
	 */
	public void setAppChannel(String appChannel) {
		this.appChannel = appChannel;
	}

	/**
	 * Returns the app version.
	 *
	 * @return the app version
	 */
	public String getAppVersion() {
		return appVersion;
	}

	/**
	 * Sets the app version.
	 *
	 * @param appVersion the app version
	 */
	public void setAppVersion(String appVersion) {
		this.appVersion = appVersion;
	}

	/**
	 * Returns the sign.
	 *
	 * @return the sign
	 */
	public String getSign() {
		return sign;
	}

	/**
	 * Sets the sign.
	 *
	 * @param sign the sign
	 */
	public void setSign(String sign) {
		this.sign = sign;
	}

	/**
	 * Returns the longitude.
	 *
	 * @return the longitude
	 */
	public double getLongitude() {
		return longitude;
	}

	/**
	 * Sets the longitude.
	 *
	 * @param longitude the longitude
	 */
	public void setLongitude(double longitude) {
		this.longitude = longitude;
	}

	/**
	 * Returns the latitude.
	 *
	 * @return the latitude
	 */
	public double getLatitude() {
		return latitude;
	}

	/**
	 * Sets the latitude.
	 *
	 * @param latitude the latitude
	 */
	public void setLatitude(double latitude) {
		this.latitude = latitude;
	}

}
