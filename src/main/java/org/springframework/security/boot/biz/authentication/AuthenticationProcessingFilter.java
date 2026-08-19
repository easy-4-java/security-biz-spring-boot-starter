package org.springframework.security.boot.biz.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.util.Objects;

/**
 * Base authentication processing filter for the security-biz starter.
 * <p>
 * Extends Spring Security's {@link AbstractAuthenticationProcessingFilter}
 * with common HTTP header handling (uid / sign / location / app metadata)
 * used by the feature-specific authentication filters in downstream starters.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public abstract class AuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	/** Default value used when the longitude/latitude headers are absent. */
	public static final String DEFAULT_LONGITUDE_LATITUDE = "0.000000";

	/**
	 * HTTP Authorization header, equal to <code>X-Uid</code>
	 */
	public static final String UID_HEADER = "X-Uid";
	/**
	 * HTTP Authorization header, equal to <code>X-Sign</code>
	 */
	public static final String SIGN_HEADER = "X-Sign";
	/**
	 * HTTP Authorization header, equal to <code>X-Longitude</code>
	 */
	public static final String LONGITUDE_HEADER = "X-Longitude";
	/**
	 * HTTP Authorization header, equal to <code>X-Latitude</code>
	 */
	public static final String LATITUDE_HEADER = "X-Latitude";
	/**
	 * HTTP Authorization header, equal to <code>X-APP-ID</code>
	 */
	public static final String APP_ID_HEADER = "X-APP-ID";
	/**
	 * HTTP Authorization header, equal to <code>X-APP-CHANNEL</code>
	 */
	public static final String APP_CHANNEL_HEADER = "X-APP-CHANNEL";
	/**
	 * HTTP Authorization header, equal to <code>X-APP-VERSION</code>
	 */
	public static final String APP_VERSION_HEADER = "X-APP-VERSION";

	/** Configurable name of the user-id header (default {@value #UID_HEADER}). */
	private String uidHeaderName = UID_HEADER;
	/** Configurable name of the signature header (default {@value #SIGN_HEADER}). */
	private String signHeaderName = SIGN_HEADER;
	/** Configurable name of the longitude header (default {@value #LONGITUDE_HEADER}). */
	private String longitudeHeaderName = LONGITUDE_HEADER;
	/** Configurable name of the latitude header (default {@value #LATITUDE_HEADER}). */
	private String latitudeHeaderName = LATITUDE_HEADER;
	/** Configurable name of the app-id header (default {@value #APP_ID_HEADER}). */
	private String appIdHeaderName = APP_ID_HEADER;
	/** Configurable name of the app-channel header (default {@value #APP_CHANNEL_HEADER}). */
	private String appChannelHeaderName = APP_CHANNEL_HEADER;
	/** Configurable name of the app-version header (default {@value #APP_VERSION_HEADER}). */
	private String appVersionHeaderName = APP_VERSION_HEADER;
	private final String format = "{} ：{}";
	
	// ~ Static fields/initializers
	// =====================================================================================
	
	protected static Logger logger = LoggerFactory.getLogger(AuthenticationProcessingFilter.class);
	
	// ~ Constructors
	// ===================================================================================================
	
	/**
	 * @param defaultFilterProcessesUrl the default value for &lt;tt&gt;filterProcessesUrl&lt;/tt&gt;.
	 */
	protected AuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
	}

	/**
	 * Creates a new instance
	 *
	 * @param requiresAuthenticationRequestMatcher the {@link RequestMatcher} used to
	 * determine if authentication is required. Cannot be null.
	 */
	protected AuthenticationProcessingFilter(
			RequestMatcher requiresAuthenticationRequestMatcher) {
		super(requiresAuthenticationRequestMatcher);
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * attempt Authentication.
	 *
	 * @param request the request
	 * @param response the response
	 * @return the result
	 */
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		if(Objects.isNull(RequestContextHolder.getRequestAttributes())) {
			// Set RequestContextHolder
			ServletRequestAttributes requestAttributes = new ServletRequestAttributes(request, response);
			RequestContextHolder.setRequestAttributes(requestAttributes, true);
		}
		
		// real method
		return this.doAttemptAuthentication(request, response);

	}
	

	/**
	 * Performs actual authentication.
	 * <p>
	 * The implementation should do one of the following:
	 * <ol>
	 * <li>Return a populated authentication token for the authenticated user, indicating
	 * successful authentication</li>
	 * <li>Return null, indicating that the authentication process is still in progress.
	 * Before returning, the implementation should perform any additional work required to
	 * complete the process.</li>
	 * <li>Throw an &lt;tt&gt;AuthenticationException&lt;/tt&gt; if the authentication process fails</li>
	 * </ol>
	 *
	 * @param request from which to extract parameters and perform the authentication
	 * @param response the response, which may be needed if the implementation has to do a
	 * redirect as part of a multi-stage authentication process (such as OpenID).
	 *
	 * @return the authenticated user token, or null if authentication is incomplete.
	 *
	 * @throws AuthenticationException if authentication fails.
	 */
	public abstract Authentication doAttemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException, IOException,
			ServletException;

	/**
	 * set Details.
	 *
	 * @param request the request
	 * @param authRequest the auth request
	 */
	protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	/**
	 * obtain Longitude.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected double obtainLongitude(HttpServletRequest request) {
		return Double.parseDouble(StringUtils.defaultIfBlank(request.getHeader(getLongitudeHeaderName()), DEFAULT_LONGITUDE_LATITUDE));
	}
	
	/**
	 * obtain Latitude.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected double obtainLatitude(HttpServletRequest request) {
		return Double.parseDouble(StringUtils.defaultIfBlank(request.getHeader(getLatitudeHeaderName()), DEFAULT_LONGITUDE_LATITUDE));
	}
	
	/**
	 * obtain Uid.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected String obtainUid(HttpServletRequest request) {
		String uid = request.getHeader(getUidHeaderName());
		logger.debug(format, getUidHeaderName(), uid);
		return uid;
	}
	
	/**
	 * obtain Sign.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected String obtainSign(HttpServletRequest request) {
		String sign = request.getHeader(getSignHeaderName());
		logger.debug(format, getSignHeaderName(), sign);
		return sign;
	}
	
	/**
	 * obtain App ID.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected String obtainAppId(HttpServletRequest request) {
		String appId = request.getHeader(getAppIdHeaderName());
		logger.debug(format,  getAppIdHeaderName(), appId);
		return appId;
	}
	
	/**
	 * obtain App Channel.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected String obtainAppChannel(HttpServletRequest request) {
		String appChannel = request.getHeader(getAppChannelHeaderName());
		logger.debug(format,  getAppChannelHeaderName(), appChannel);
		return appChannel;
	}
	
	/**
	 * obtain App Version.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected String obtainAppVersion(HttpServletRequest request) {
		String appVersion = request.getHeader(getAppVersionHeaderName());
		logger.debug(format,  getAppVersionHeaderName(), appVersion);
		return appVersion;
	}
	
	/**
	 * Returns the uid header name.
	 *
	 * @return the uid header name
	 */
	public String getUidHeaderName() {
		return uidHeaderName;
	}

	/**
	 * Sets the uid header name.
	 *
	 * @param uidHeaderName the uid header name
	 */
	public void setUidHeaderName(String uidHeaderName) {
		this.uidHeaderName = uidHeaderName;
	}
	
	/**
	 * Returns the sign header name.
	 *
	 * @return the sign header name
	 */
	public String getSignHeaderName() {
		return signHeaderName;
	}

	/**
	 * Sets the sign header name.
	 *
	 * @param signHeaderName the sign header name
	 */
	public void setSignHeaderName(String signHeaderName) {
		this.signHeaderName = signHeaderName;
	}

	/**
	 * Returns the longitude header name.
	 *
	 * @return the longitude header name
	 */
	public String getLongitudeHeaderName() {
		return longitudeHeaderName;
	}

	/**
	 * Sets the longitude header name.
	 *
	 * @param longitudeHeaderName the longitude header name
	 */
	public void setLongitudeHeaderName(String longitudeHeaderName) {
		this.longitudeHeaderName = longitudeHeaderName;
	}

	/**
	 * Returns the latitude header name.
	 *
	 * @return the latitude header name
	 */
	public String getLatitudeHeaderName() {
		return latitudeHeaderName;
	}

	/**
	 * Sets the latitude header name.
	 *
	 * @param latitudeHeaderName the latitude header name
	 */
	public void setLatitudeHeaderName(String latitudeHeaderName) {
		this.latitudeHeaderName = latitudeHeaderName;
	}

	/**
	 * Returns the app id header name.
	 *
	 * @return the app id header name
	 */
	public String getAppIdHeaderName() {
		return appIdHeaderName;
	}

	/**
	 * Sets the app id header name.
	 *
	 * @param appIdHeaderName the app id header name
	 */
	public void setAppIdHeaderName(String appIdHeaderName) {
		this.appIdHeaderName = appIdHeaderName;
	}

	/**
	 * Returns the app channel header name.
	 *
	 * @return the app channel header name
	 */
	public String getAppChannelHeaderName() {
		return appChannelHeaderName;
	}

	/**
	 * Sets the app channel header name.
	 *
	 * @param appChannelHeaderName the app channel header name
	 */
	public void setAppChannelHeaderName(String appChannelHeaderName) {
		this.appChannelHeaderName = appChannelHeaderName;
	}

	/**
	 * Returns the app version header name.
	 *
	 * @return the app version header name
	 */
	public String getAppVersionHeaderName() {
		return appVersionHeaderName;
	}

	/**
	 * Sets the app version header name.
	 *
	 * @param appVersionHeaderName the app version header name
	 */
	public void setAppVersionHeaderName(String appVersionHeaderName) {
		this.appVersionHeaderName = appVersionHeaderName;
	}
	
}
