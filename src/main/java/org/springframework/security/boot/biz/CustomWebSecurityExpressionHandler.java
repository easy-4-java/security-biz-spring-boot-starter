package org.springframework.security.boot.biz;

import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * <p>Handler for Custom Web Security Expression.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class CustomWebSecurityExpressionHandler extends DefaultHttpSecurityExpressionHandler {

    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private String defaultRolePrefix = "ROLE_";

    /**
     * create Security Expression Root.
     *
     * @param authentication the authentication
     * @param context the context
     * @return the result
     */
    @Override
    protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
                                                                         RequestAuthorizationContext context) {
        WebSecurityExpressionRoot root = new CustomWebSecurityExpressionRoot(authentication, context);
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(this.trustResolver);
        root.setRoleHierarchy(this.getRoleHierarchy());
        root.setDefaultRolePrefix(this.defaultRolePrefix);
        return root;
    }

    /**
     * Sets the trust resolver.
     *
     * @param trustResolver the trust resolver
     */
    @Override
    public void setTrustResolver(AuthenticationTrustResolver trustResolver){
        super.setTrustResolver(trustResolver);
        this.trustResolver = trustResolver;
    }

    /**
     * Sets the default role prefix.
     *
     * @param defaultRolePrefix the default role prefix
     */
    @Override
    public void setDefaultRolePrefix(String defaultRolePrefix) {
        super.setDefaultRolePrefix(defaultRolePrefix);
        this.defaultRolePrefix = defaultRolePrefix;
    }

}
