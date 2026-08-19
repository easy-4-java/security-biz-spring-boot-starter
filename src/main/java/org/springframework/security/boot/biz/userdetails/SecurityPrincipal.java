package org.springframework.security.boot.biz.userdetails;

import io.github.easy4j.jwt.JwtPayload;
import io.github.easy4j.jwt.JwtPayload.RolePair;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class SecurityPrincipal extends User implements Cloneable {

	protected static final String ADMIN_STRING = "admin";

	/**
	 * 用户ID（用户来源表Id）
	 */
	private String uid;
	/**
	 * 用户UID（用户编号）
	 */
	private String uuid;
	/**
	 * 用户Key（用户编号）
	 */
	private String ukey;
	/**
	 * 用户Code（内部工号）
	 */
	private String ucode;
	/**
	 * 角色ID（角色表Id）
	 */
	private String rid;
	/**
	 * 角色Key：角色业务表中的唯一ID
	 */
	private String rkey;
	/**
	 * 角色Code：角色业务表中的唯一编码
	 */
	private String rcode;
	/**
   	 * 用户是否绑定信息
   	 */
    private boolean bound = Boolean.FALSE;
    /**
   	 * 用户是否完善信息
   	 */
    private boolean initial = Boolean.FALSE;
	/**
	 * 用户是否需要多因子验证
	 */
	private boolean verify = Boolean.FALSE;
    /**
	 * 请求参数签名（可选）
	 */
	private String sign;
	/**
	 * 授权方式（可选）
	 */
	private String authType;
	/**
	 * 用户最新经度（可选）
	 */
	private double longitude;
	/**
	 * 用户最新纬度（可选）
	 */
	private double latitude;
	/**
	 * 用户拥有角色列表
	 */
	private List<RolePair> roles;
	/**
	 * 用户权限标记列表
	 */
	private Set<String> perms = new HashSet<>();
	/**
	 * 用户数据
	 */
	private Map<String, Object> profile = new HashMap<String, Object>();

	/**
	 * Constructs a new security principal instance.
	 *
	 * @param username the username
	 * @param password the password
	 * @param roles the roles
	 */
	public SecurityPrincipal(String username, String password, String... roles) {
		super(username, password, roleAuthorities(Arrays.asList(roles)));
	}

	/**
	 * role Authorities.
	 *
	 * @param roles the roles
	 * @return the result
	 */
	public static Collection<? extends GrantedAuthority> roleAuthorities(List<String> roles) {
		if (roles == null) {
			throw new InsufficientAuthenticationException("User has no roles assigned");
		}
		List<GrantedAuthority> authorities = roles.stream().map(authority -> new SimpleGrantedAuthority(authority))
				.collect(Collectors.toList());

		return authorities;
	}

	/**
	 * Constructs a new security principal instance.
	 *
	 * @param username the username
	 * @param password the password
	 * @param authorities the authorities
	 */
	public SecurityPrincipal(String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
	}

	/**
	 * Constructs a new security principal instance.
	 *
	 * @param username the username
	 * @param password the password
	 * @param enabled the enabled
	 * @param accountNonExpired the account non expired
	 * @param credentialsNonExpired the credentials non expired
	 * @param accountNonLocked the account non locked
	 * @param authorities the authorities
	 */
	public SecurityPrincipal(String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
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
	 * Returns the uuid.
	 *
	 * @return the uuid
	 */
	public String getUuid() {
		return uuid;
	}

	/**
	 * Sets the uuid.
	 *
	 * @param uuid the uuid
	 */
	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	/**
	 * Returns the ukey.
	 *
	 * @return the ukey
	 */
	public String getUkey() {
		return ukey;
	}

	/**
	 * Sets the ukey.
	 *
	 * @param ukey the ukey
	 */
	public void setUkey(String ukey) {
		this.ukey = ukey;
	}

	/**
	 * Returns the ucode.
	 *
	 * @return the ucode
	 */
	public String getUcode() {
		return ucode;
	}

	/**
	 * Sets the ucode.
	 *
	 * @param ucode the ucode
	 */
	public void setUcode(String ucode) {
		this.ucode = ucode;
	}

	/**
	 * Returns the rid.
	 *
	 * @return the rid
	 */
	public String getRid() {
		return rid;
	}

	/**
	 * Sets the rid.
	 *
	 * @param rid the rid
	 */
	public void setRid(String rid) {
		this.rid = rid;
	}

	/**
	 * Returns the rkey.
	 *
	 * @return the rkey
	 */
	public String getRkey() {
		return rkey;
	}

	/**
	 * Sets the rkey.
	 *
	 * @param rkey the rkey
	 */
	public void setRkey(String rkey) {
		this.rkey = rkey;
	}

	/**
	 * Returns the rcode.
	 *
	 * @return the rcode
	 */
	public String getRcode() {
		return rcode;
	}

	/**
	 * Sets the rcode.
	 *
	 * @param rcode the rcode
	 */
	public void setRcode(String rcode) {
		this.rcode = rcode;
	}

	/**
	 * Returns the bound.
	 *
	 * @return the bound
	 */
	public boolean isBound() {
		return bound;
	}

	/**
	 * Sets the bound.
	 *
	 * @param bound the bound
	 */
	public void setBound(boolean bound) {
		this.bound = bound;
	}

	/**
	 * Returns the initial.
	 *
	 * @return the initial
	 */
	public boolean isInitial() {
		return initial;
	}

	/**
	 * Sets the initial.
	 *
	 * @param initial the initial
	 */
	public void setInitial(boolean initial) {
		this.initial = initial;
	}

	/**
	 * Sets the verify.
	 *
	 * @param verify the verify
	 */
	public void setVerify(boolean verify) {
		this.verify = verify;
	}

	/**
	 * Returns the verify.
	 *
	 * @return the verify
	 */
	public boolean isVerify() {
		return verify;
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
	 * Returns the auth type.
	 *
	 * @return the auth type
	 */
	public String getAuthType() {
		return authType;
	}

	/**
	 * Sets the auth type.
	 *
	 * @param authType the auth type
	 */
	public void setAuthType(String authType) {
		this.authType = authType;
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

	/**
	 * Returns the roles.
	 *
	 * @return the roles
	 */
	public List<JwtPayload.RolePair> getRoles() {
		return roles;
	}

	/**
	 * Sets the roles.
	 *
	 * @param roles the roles
	 */
	public void setRoles(List<RolePair> roles) {
		this.roles = roles;
	}

	/**
	 * Returns the perms.
	 *
	 * @return the perms
	 */
	public Set<String> getPerms() {
		return perms;
	}

	/**
	 * Sets the perms.
	 *
	 * @param perms the perms
	 */
	public void setPerms(Set<String> perms) {
		this.perms = perms;
	}

	/**
	 * Returns the profile.
	 *
	 * @return the profile
	 */
	public Map<String, Object> getProfile() {
		return profile;
	}

	/**
	 * Sets the profile.
	 *
	 * @param profile the profile
	 */
	public void setProfile(Map<String, Object> profile) {
		this.profile = profile;
	}

	/**
	 * Returns the admin.
	 *
	 * @return the admin
	 */
	public boolean isAdmin() {
		if(CollectionUtils.isEmpty(roles)) {
			return false;
		}
		return CollectionUtils.contains(getRoles().iterator(), ADMIN_STRING) || StringUtils.equalsIgnoreCase(ADMIN_STRING, this.getRkey()) || StringUtils.equalsIgnoreCase(ADMIN_STRING, this.getRid());
	}

	/**
	 * Determines whether has role.
	 *
	 * @param role the role
	 * @return the result
	 */
	public boolean hasRole(String role) {
		if(!StringUtils.isNoneBlank(role)) {
			return false;
		}
		if(CollectionUtils.isEmpty(roles)) {
			return false;
		}
		return roles.stream().anyMatch(entry -> StringUtils.equalsIgnoreCase(entry.getKey(), role));
	}

	/**
	 * Determines whether has any role.
	 *
	 * @param roles the roles
	 * @return the result
	 */
	public boolean hasAnyRole(String... roles) {
		if(!StringUtils.isNoneBlank(roles)) {
			return false;
		}
		if(CollectionUtils.isEmpty(getRoles())) {
			return false;
		}
		return CollectionUtils.containsAny(getRoles(), Arrays.asList(roles));
	}

	/**
	 * Determines whether equals.
	 *
	 * @param o the o
	 * @return the result
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		SecurityPrincipal user = (SecurityPrincipal) o;
		if (uid != null ? !uid.equals(user.getUid()) : user.getUid() != null) {
			return false;
		}
		return true;
	}

	/**
	 * hash Code.
	 *
	 * @return the result
	 */
	@Override
	public int hashCode() {
		return uid != null ? uid.hashCode() : 0;
	}

	/**
	 * to String.
	 *
	 * @return the result
	 */
	@Override
	public String toString() {
		return " User {" + "userid=" + uid + ", username='" + getUsername() + '\'' + ", password='" + getPassword()
				+ '\'' + ", enabled='" + isEnabled() + '\'' + ", accountNonExpired="
				+ isAccountNonExpired() + ", credentialsNonExpired=" + isCredentialsNonExpired() + ", accountNonLocked="
				+ isAccountNonLocked() + '}';
	}


	/**
	 * to Payload.
	 *
	 * @return the result
	 */
	public UserProfilePayload toPayload(){

		UserProfilePayload payload = new UserProfilePayload();

		payload.setUid(this.getUid());
		payload.setUuid(this.getUuid());
		payload.setUkey(this.getUkey());
		payload.setUcode(this.getUcode());
		payload.setPerms(new HashSet<String>(perms));
		payload.setRid(this.getRid());
		payload.setRkey(this.getRkey());
		payload.setRcode(this.getRcode());
		payload.setRoles(this.getRoles());
		payload.setBound(this.isBound());
		payload.setInitial(this.isInitial());
		payload.setVerify(this.isVerify());

		if (CollectionUtils.isEmpty(this.getProfile())) {
			payload.setProfile(new HashMap<>(0));
		} else {
			payload.setProfile(this.getProfile());
		}
		return payload;

	}

}
