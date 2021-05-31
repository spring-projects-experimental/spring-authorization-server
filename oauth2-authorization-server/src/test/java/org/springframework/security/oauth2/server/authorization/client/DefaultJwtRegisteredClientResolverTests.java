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
package org.springframework.security.oauth2.server.authorization.client;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DefaultJwtRegisteredClientResolverTests {

	private RegisteredClientRepository registeredClientRepository;
	private JwtToRegisteredClientResolver jwtToRegisteredClientResolver;

	@Before
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.jwtToRegisteredClientResolver = new DefaultJwtToRegisteredClientResolver(registeredClientRepository);
	}

	@Test
	public void constructorWithRegisteredClientRepositoryNullThenThrow() {
		assertThatThrownBy(() -> new DefaultJwtToRegisteredClientResolver(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void whenIssuerMatchesShouldReturnClient() {
		RegisteredClient rc = new RegisteredClient.Builder("123")
				.clientId("test1")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.redirectUri("https://localhost")
				.build();
		Jwt jwt = new Jwt("123", Instant.now(), Instant.now().plusSeconds(300),
				map("kid", "123"), map("iss", "test1", "sub", "test2"));
		when(registeredClientRepository.findByClientId("test1")).thenReturn(rc);
		assertThat(jwtToRegisteredClientResolver.resolve(jwt)).isEqualTo(rc);
	}

	@Test
	public void whenSubjectMatchesShouldReturnClient() {
		RegisteredClient rc = new RegisteredClient.Builder("123")
				.clientId("test1")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.redirectUri("https://localhost")
				.build();
		Jwt jwt = new Jwt("123", Instant.now(), Instant.now().plusSeconds(300),
				map("kid", "123"), map("iss", "test1", "sub", "test2"));
		when(registeredClientRepository.findByClientId("test2")).thenReturn(rc);
		assertThat(jwtToRegisteredClientResolver.resolve(jwt)).isEqualTo(rc);
	}

	@Test
	public void whenNothingMatchesShouldReturnNull() {
		RegisteredClient rc = new RegisteredClient.Builder("123")
				.clientId("test1")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.redirectUri("https://localhost")
				.build();
		Jwt jwt = new Jwt("123", Instant.now(), Instant.now().plusSeconds(300),
				map("kid", "123"), map("iss", "test3", "sub", "test4"));
		when(registeredClientRepository.findByClientId("test1")).thenReturn(rc);
		when(registeredClientRepository.findByClientId("test2")).thenReturn(rc);
		assertThat(jwtToRegisteredClientResolver.resolve(jwt)).isNull();
	}

	// TODO is there similar function somewhere in accessible Spring libraries ?
	private static <K, V> Map<K, V> map(Object...args) {
		HashMap<K, V> m = new HashMap<>();
		for (int i = 1; i < args.length; i+=2) {
			m.put((K) args[i-1], (V) args[i]);
		}
		return m;
	}
}
