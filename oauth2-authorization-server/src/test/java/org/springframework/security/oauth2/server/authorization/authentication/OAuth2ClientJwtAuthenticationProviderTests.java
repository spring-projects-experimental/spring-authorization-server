/*
 * Copyright 2002-2020 the original author or authors.
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
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod2;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JwtToRegisteredClientResolver;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OAuth2ClientJwtAuthenticationProviderTests {

	private JwtDecoder jwtDecoder;
	private JwtToRegisteredClientResolver resolver;
	private OAuth2AuthorizationService authorizationService;
	private OAuth2ClientJwtAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.resolver = mock(JwtToRegisteredClientResolver.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.jwtDecoder = mock(JwtDecoder.class);
		this.authenticationProvider = new OAuth2ClientJwtAuthenticationProvider(
				this.resolver, authorizationService, this.jwtDecoder);
	}

	private void shouldThrow(Authentication auth, String errorCode) {
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(auth))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(errorCode);
	}

	private <K, V> Map<K, V> map(Object...objs) {
		Map<K, V> m = new HashMap<>();
		for (int i = 1; i < objs.length; i+=2) {
			m.put((K) objs[i-1], (V) objs[i]);
		}
		return m;
	}

	@Test
	public void constructorWhenJwtToRegisteredClientResolverNullThenThrow() {
		assertThatThrownBy(() -> new OAuth2ClientJwtAuthenticationProvider(null, authorizationService, jwtDecoder))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtToRegisteredClientResolver cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrow() {
		assertThatThrownBy(() -> new OAuth2ClientJwtAuthenticationProvider(this.resolver, null, jwtDecoder))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenJwtDecoderNullThenThrow() {
		assertThatThrownBy(() -> new OAuth2ClientJwtAuthenticationProvider(this.resolver, authorizationService, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtDecoder cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2ClientAssertionAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2ClientAssertionAuthenticationToken.class));
	}

	@Test
	public void authenticateWhenJwtDecoderThrowsThenThrow() {
		Authentication auth = new OAuth2ClientAssertionAuthenticationToken(
				"...", ClientAuthenticationMethod2.JWT, null);
		when(this.jwtDecoder.decode("...")).thenThrow(new JwtException("bigbadaboom"));
		shouldThrow(auth, OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenJwtDecoderReturnsNullThenThrow() {
		Authentication auth = new OAuth2ClientAssertionAuthenticationToken(
				"...", ClientAuthenticationMethod2.JWT, null);
		when(this.jwtDecoder.decode("...")).thenReturn(null);
		shouldThrow(auth, OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenSubjectNotFoundThenThrow() {
		Authentication auth = new OAuth2ClientAssertionAuthenticationToken(
				"...", ClientAuthenticationMethod2.JWT, null);
		Jwt jwt = new Jwt("123", Instant.now().minusSeconds(30), Instant.now().plusSeconds(30),
				map("kid", "123"), map("sub", "client-2"));
		when(this.jwtDecoder.decode("...")).thenReturn(jwt);
		shouldThrow(auth, OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientAuthenticationMethodNotAllowedThenThrow() {
		Authentication auth = new OAuth2ClientAssertionAuthenticationToken(
				"...", ClientAuthenticationMethod2.JWT, null);
		Jwt jwt = new Jwt("123", Instant.now().minusSeconds(30), Instant.now().plusSeconds(30),
				map("kid", "123"), map("sub", "client-1"));
		RegisteredClient rc = TestRegisteredClients.registeredClient().build();
		when(this.jwtDecoder.decode("...")).thenReturn(jwt);
		when(this.resolver.resolve(any())).thenReturn(rc);
		shouldThrow(auth, OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientAuthenticationAllowedThenAuthenticate() {
		Authentication auth = new OAuth2ClientAssertionAuthenticationToken(
				"...", ClientAuthenticationMethod2.JWT, null);
		Jwt jwt = new Jwt("123", Instant.now().minusSeconds(30), Instant.now().plusSeconds(30),
				map("kid", "123"), map("sub", "client-1"));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod2.JWT).build();
		when(this.jwtDecoder.decode("...")).thenReturn(jwt);
		when(this.resolver.resolve(any())).thenReturn(registeredClient);
		OAuth2ClientAuthenticationToken auth1 = (OAuth2ClientAuthenticationToken) authenticationProvider.authenticate(auth);
		assertThat(auth1).isNotNull();
		assertThat(auth1.isAuthenticated()).isTrue();
		assertThat(auth1.getPrincipal().toString()).isEqualTo(registeredClient.getClientId());
		assertThat(auth1.getCredentials()).isNull();
		assertThat(auth1.getRegisteredClient()).isEqualTo(registeredClient);
	}
}
