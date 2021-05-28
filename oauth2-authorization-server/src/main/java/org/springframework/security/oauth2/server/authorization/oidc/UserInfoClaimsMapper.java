package org.springframework.security.oauth2.server.authorization.oidc;

import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

public interface UserInfoClaimsMapper {

	OidcUserInfo map(Object principal);

}
