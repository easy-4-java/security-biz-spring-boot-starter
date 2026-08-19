package org.springframework.security.boot.biz;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.util.Objects;

/**
 * <p>Custom Web Security Expression Root.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class CustomWebSecurityExpressionRoot  extends WebSecurityExpressionRoot {

    // private FilterInvocation filterInvocation;
    /** Allows direct access to the request object */
    public final HttpServletRequest request;

    /**
     * Constructs a new custom web security expression root instance.
     *
     * @param a the a
     * @param fi the fi
     */
    public CustomWebSecurityExpressionRoot(Authentication a, FilterInvocation fi) {
        super(a, fi);
        this.request = fi.getRequest();
    }

    /**
     * Constructs a new custom web security expression root instance.
     *
     * @param authentication the authentication
     * @param context the context
     */
    public CustomWebSecurityExpressionRoot(Authentication authentication, RequestAuthorizationContext context) {
        super(() -> authentication, context);
        this.request = context.getRequest();
    }

    /**
     * Takes a specific IP address or a range using the IP/Netmask (e.g. 192.168.1.0/24 or
     * 202.24.0.0/14).
     *
     * @param ipAddress the address or range of addresses from which the request must
     * come.
     * @return true if the IP address of the current request is in the required range.
     */
    @Override
    public boolean hasIpAddress(String ipAddress) {
        String remoteAddr = Objects.toString(request.getRemoteAddr(), "");
        return (new IpAddressMatcher(ipAddress).matches(remoteAddr));
    }

}
