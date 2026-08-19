package org.springframework.security.boot.biz.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Rest 模式登录认证绑定的参数对象Model
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class PostLoginRequest {
	
	/**
	 * 认证账号（必选）
	 */
    private String username;
    /**
   	 * 认证密码（必选）
   	 */
    private String password;
    /**
   	 * 验证码（可选）
   	 */
    private String captcha;
	
    /**
     * Constructs a new post login request instance.
     *
     */
    @JsonCreator
    public PostLoginRequest(@JsonProperty("username") String username, @JsonProperty("password") String password, @JsonProperty("captcha") String captcha) {
        this.username = username;
        this.password = password;
        this.captcha = captcha;
    }

    /**
     * Returns the username.
     *
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Returns the password.
     *
     * @return the password
     */
    public String getPassword() {
        return password;
    }

	/**
	 * Returns the captcha.
	 *
	 * @return the captcha
	 */
	public String getCaptcha() {
		return captcha;
	}

	/**
	 * Sets the captcha.
	 *
	 * @param captcha the captcha
	 */
	public void setCaptcha(String captcha) {
		this.captcha = captcha;
	}

	/**
	 * Sets the username.
	 *
	 * @param username the username
	 */
	public void setUsername(String username) {
		this.username = username;
	}

	/**
	 * Sets the password.
	 *
	 * @param password the password
	 */
	public void setPassword(String password) {
		this.password = password;
	}
	
}
