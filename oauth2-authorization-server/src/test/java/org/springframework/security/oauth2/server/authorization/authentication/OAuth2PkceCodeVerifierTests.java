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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OAuth2PkceCodeVerifierTests {

	private static final String PLAIN_CODE_VERIFIER = "pkce-key";
	private static final String PLAIN_CODE_CHALLENGE = PLAIN_CODE_VERIFIER;

	// See RFC 7636: Appendix B.  Example for the S256 code_challenge_method
	// https://tools.ietf.org/html/rfc7636#appendix-B
	private static final String S256_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	private static final String S256_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

	private static final String AUTHORIZATION_CODE = "code";
	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

	private OAuth2AuthorizationService authorizationService;
	private OAuth2PkceCodeVerifier pkceCodeVerifier;

	@Before
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.pkceCodeVerifier = new OAuth2PkceCodeVerifier(authorizationService);
	}

	private <K, V> Map<K, V> map(Object...objs) {
		Map<K, V> m = new HashMap<>();
		for (int i = 1; i < objs.length; i+=2) {
			m.put((K) objs[i-1], (V) objs[i]);
		}
		return m;
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrow() {
		assertThatThrownBy(() -> new OAuth2PkceCodeVerifier(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void authenticateWithEmptyParametersShouldReturnFalse() {
		assertThat(pkceCodeVerifier.authenticatePkceIfAvailable(Collections.emptyMap(), null)).isFalse();
	}

	@Test
	public void authenticationWithNonCodeGrantShouldReturnFalse() {
		Map<String, Object> params = map(
				OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS,
				OAuth2ParameterNames.CODE, "123");
		assertThat(pkceCodeVerifier.authenticatePkceIfAvailable(params, null)).isFalse();
	}

	@Test
	public void authenticateWithCodeGrantButMissingCodeShouldReturnFalse() {
		Map<String, Object> params = map(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(pkceCodeVerifier.authenticatePkceIfAvailable(params, null)).isFalse();
	}

	@Test
	public void whenPkceInvalidCodeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, createPkceAuthorizationParametersPlain())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);

		Map<String, Object> parameters = createPkceTokenParameters(PLAIN_CODE_VERIFIER);
		parameters.put(OAuth2ParameterNames.CODE, "invalid-code");

		shouldThrow(parameters, registeredClient, OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void whenPkceAndRequireProofKeyAndMissingCodeChallengeThenThrow() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSettings(clientSettings -> clientSettings.requireProofKey(true))
				.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient)
				.build();

		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);

		Map<String, Object> parameters = createPkceTokenParameters(PLAIN_CODE_VERIFIER);

		shouldThrow(parameters, registeredClient, OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void whenPkceAndMissingCodeVerifierThenThrow() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, createPkceAuthorizationParametersPlain())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);
		Map<String, Object> parameters = createPkceTokenParameters(PLAIN_CODE_VERIFIER);
		parameters.remove(PkceParameterNames.CODE_VERIFIER);

		shouldThrow(parameters, registeredClient, OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void whenPkceAndPlainMethodAndInvalidCodeVerifierThenThrow() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, createPkceAuthorizationParametersPlain())
				.build();

		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);

		Map<String, Object> parameters = createPkceTokenParameters("invalid-code-verifier");

		shouldThrow(parameters, registeredClient, OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void whenPkcsAndS256AndInvalidCodeVerifierThenThrow() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, createPkceAuthorizationParametersS256())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);
		Map<String, Object> parameters = createPkceTokenParameters("invalid-code-verifier");
		shouldThrow(parameters, registeredClient, OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void whenPkceAndPlainMethodAndValidCodeVerifierThenReturnTrue() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, createPkceAuthorizationParametersPlain())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);

		Map<String, Object> parameters = createPkceTokenParameters(PLAIN_CODE_VERIFIER);

		assertThat(pkceCodeVerifier.authenticatePkceIfAvailable(parameters, registeredClient)).isTrue();
	}

	@Test
	public void whenPkceAndMissingMethodThenDefaultPlainMethodAndReturnTrue() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient().build();
		Map<String, Object> authorizationRequestAdditionalParameters = createPkceAuthorizationParametersPlain();
		authorizationRequestAdditionalParameters.remove(PkceParameterNames.CODE_CHALLENGE_METHOD);
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, authorizationRequestAdditionalParameters)
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);
		Map<String, Object> parameters = createPkceTokenParameters(PLAIN_CODE_VERIFIER);

		assertThat(pkceCodeVerifier.authenticatePkceIfAvailable(parameters, registeredClient)).isTrue();
	}

	@Test
	public void testPkceAndS256MethodAndValidCodeVerifierThenReturnTrue() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, createPkceAuthorizationParametersS256())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);
		Map<String, Object> parameters = createPkceTokenParameters(S256_CODE_VERIFIER);

		assertThat(pkceCodeVerifier.authenticatePkceIfAvailable(parameters, registeredClient)).isTrue();
	}

	@Test
	public void testPkceAndUnsupportedCodeChallengeMethodThenThrow() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient().build();
		Map<String, Object> authorizationRequestAdditionalParameters = createPkceAuthorizationParametersPlain();
		// This should never happen: the Authorization endpoint should not allow it
		authorizationRequestAdditionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "unsupported-challenge-method");
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, authorizationRequestAdditionalParameters)
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);
		Map<String, Object> parameters = createPkceTokenParameters(PLAIN_CODE_VERIFIER);

		shouldThrow(parameters, registeredClient, OAuth2ErrorCodes.SERVER_ERROR);
	}

	private void shouldThrow(Map<String, Object> parameters, RegisteredClient registeredClient, String errorCode) {
		assertThatThrownBy(() -> this.pkceCodeVerifier.authenticatePkceIfAvailable(parameters, registeredClient))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(errorCode);
	}

	private static Map<String, Object> createPkceTokenParameters(String codeVerifier) {
		Map<String, Object> parameters = new HashMap<>();
		parameters.put(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		parameters.put(OAuth2ParameterNames.CODE, AUTHORIZATION_CODE);
		parameters.put(PkceParameterNames.CODE_VERIFIER, codeVerifier);
		return parameters;
	}

	private static Map<String, Object> createPkceAuthorizationParametersPlain() {
		Map<String, Object> parameters = new HashMap<>();
		parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "plain");
		parameters.put(PkceParameterNames.CODE_CHALLENGE, PLAIN_CODE_CHALLENGE);
		return parameters;
	}

	private static Map<String, Object> createPkceAuthorizationParametersS256() {
		Map<String, Object> parameters = new HashMap<>();
		parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		parameters.put(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE);
		return parameters;
	}

}
