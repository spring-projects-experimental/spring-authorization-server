/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JwtToRegisteredClientResolver;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;


/**
 * Client authentication provider handling JWT assertions
 *
 * @author Rafal Lewczuk
 * @since 0.1.2
 */
public class OAuth2ClientJwtAuthenticationProvider implements AuthenticationProvider {
	private final JwtToRegisteredClientResolver jwtToRegisteredClientResolver;
	private final OAuth2PkceCodeVerifier pkceCodeVerifier;
	private final JwtDecoder jwtDecoder;

	public OAuth2ClientJwtAuthenticationProvider(JwtToRegisteredClientResolver jwtToRegisteredClientResolver,
			OAuth2AuthorizationService authorizationService, JwtDecoder jwtDecoder) {
		Assert.notNull(jwtToRegisteredClientResolver, "jwtToRegisteredClientResolver cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwtDecoder, "jwtDecoder cannot be null");
		this.pkceCodeVerifier = new OAuth2PkceCodeVerifier(authorizationService);
		this.jwtToRegisteredClientResolver = jwtToRegisteredClientResolver;
		this.jwtDecoder = jwtDecoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAssertionAuthenticationToken clientAuthentication = (OAuth2ClientAssertionAuthenticationToken) authentication;

		if (!ClientAuthenticationMethod2.JWT.equals(clientAuthentication.getClientAuthenticationMethod())) {
			return null; // only JWT assertions are supported by this provider
		}

		Jwt jwt;

		try {
			jwt = this.jwtDecoder.decode(clientAuthentication.getClientAssertion());
		} catch (JwtException e) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}

		if (jwt == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}

		RegisteredClient registeredClient = this.jwtToRegisteredClientResolver.resolve(jwt);
		if (registeredClient == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}

		if (!registeredClient.getClientAuthenticationMethods().contains(
				clientAuthentication.getClientAuthenticationMethod())) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}

		pkceCodeVerifier.authenticatePkceIfAvailable(clientAuthentication.getAdditionalParameters(), registeredClient);

		return new OAuth2ClientAuthenticationToken(registeredClient);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAssertionAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
