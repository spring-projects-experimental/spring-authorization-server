/*
 * Copyright 2020-2021 the original author or authors.
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
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation used for authenticating an OAuth 2.0 Client.
 *
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 * @author Daniel Garnier-Moiroux
 * @since 0.0.1
 * @see OAuth2ClientAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see PasswordEncoder
 */
public class OAuth2ClientAuthenticationProvider implements AuthenticationProvider {
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2PkceCodeVerifier pkceCodeVerifier;
	private PasswordEncoder passwordEncoder;

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService
	 */
	public OAuth2ClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.pkceCodeVerifier = new OAuth2PkceCodeVerifier(authorizationService);
		this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	/**
	 * Sets the {@link PasswordEncoder} used to validate
	 * the {@link RegisteredClient#getClientSecret() client secret}.
	 * If not set, the client secret will be compared using
	 * {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}.
	 *
	 * @param passwordEncoder the {@link PasswordEncoder} used to validate the client secret
	 */
	public final void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication =
				(OAuth2ClientAuthenticationToken) authentication;

		String clientId = clientAuthentication.getPrincipal().toString();
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throwInvalidClient();
		}

		if (!registeredClient.getClientAuthenticationMethods().contains(
				clientAuthentication.getClientAuthenticationMethod())) {
			throwInvalidClient();
		}

		boolean authenticatedCredentials = false;

		if (clientAuthentication.getCredentials() != null) {
			String clientSecret = clientAuthentication.getCredentials().toString();
			if (!this.passwordEncoder.matches(clientSecret, registeredClient.getClientSecret())) {
				throwInvalidClient();
			}
			authenticatedCredentials = true;
		}

		authenticatedCredentials = authenticatedCredentials ||
				pkceCodeVerifier.authenticatePkceIfAvailable(clientAuthentication.getAdditionalParameters(), registeredClient);
		if (!authenticatedCredentials) {
			throwInvalidClient();
		}

		return new OAuth2ClientAuthenticationToken(registeredClient);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static void throwInvalidClient() {
		throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
	}
}
