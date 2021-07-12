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

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken2;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.entry;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2RefreshTokenAuthenticationProvider}.
 *
 * @author Alexey Nesterov
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @since 0.0.3
 */
public class OAuth2RefreshTokenAuthenticationProviderTests {
	private OAuth2AuthorizationService authorizationService;
	private JwtEncoder jwtEncoder;
	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;
	private OAuth2RefreshTokenAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.jwtEncoder = mock(JwtEncoder.class);
		when(this.jwtEncoder.encode(any(), any())).thenReturn(createJwt(Collections.singleton("scope1")));
		this.authenticationProvider = new OAuth2RefreshTokenAuthenticationProvider(
				this.authorizationService, this.jwtEncoder);
		this.jwtCustomizer = mock(OAuth2TokenCustomizer.class);
		this.authenticationProvider.setJwtCustomizer(this.jwtCustomizer);
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationProvider(null, this.jwtEncoder))
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenJwtEncoderNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationProvider(this.authorizationService, null))
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("jwtEncoder cannot be null");
	}

	@Test
	public void setJwtCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authenticationProvider.setJwtCustomizer(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtCustomizer cannot be null");
	}

	@Test
	public void supportsWhenSupportedAuthenticationThenTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2RefreshTokenAuthenticationToken.class)).isTrue();
	}

	@Test
	public void supportsWhenUnsupportedAuthenticationThenFalse() {
		assertThat(this.authenticationProvider.supports(OAuth2ClientCredentialsAuthenticationToken.class)).isFalse();
	}

	@Test
	public void authenticateWhenValidRefreshTokenThenReturnAccessToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<JwtEncodingContext> jwtEncodingContextCaptor = ArgumentCaptor.forClass(JwtEncodingContext.class);
		verify(this.jwtCustomizer).customize(jwtEncodingContextCaptor.capture());
		JwtEncodingContext jwtEncodingContext = jwtEncodingContextCaptor.getValue();
		assertThat(jwtEncodingContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(jwtEncodingContext.<Authentication>getPrincipal()).isEqualTo(authorization.getAttribute(Principal.class.getName()));
		assertThat(jwtEncodingContext.getAuthorization()).isEqualTo(authorization);
		assertThat(jwtEncodingContext.getAuthorizedScopes())
				.isEqualTo(authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME));
		assertThat(jwtEncodingContext.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(jwtEncodingContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.REFRESH_TOKEN);
		assertThat(jwtEncodingContext.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant()).isEqualTo(authentication);
		assertThat(jwtEncodingContext.getHeaders()).isNotNull();
		assertThat(jwtEncodingContext.getClaims()).isNotNull();

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getRegisteredClient().getId()).isEqualTo(updatedAuthorization.getRegisteredClientId());
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(accessTokenAuthentication.getAccessToken()).isEqualTo(updatedAuthorization.getAccessToken().getToken());
		assertThat(updatedAuthorization.getAccessToken()).isNotEqualTo(authorization.getAccessToken());
		assertThat(accessTokenAuthentication.getRefreshToken()).isEqualTo(updatedAuthorization.getRefreshToken().getToken());
		// By default, refresh token is reused
		assertThat(updatedAuthorization.getRefreshToken()).isEqualTo(authorization.getRefreshToken());
	}

	@Test
	public void authenticateWhenValidRefreshTokenThenReturnIdToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<JwtEncodingContext> jwtEncodingContextCaptor = ArgumentCaptor.forClass(JwtEncodingContext.class);
		verify(this.jwtCustomizer, times(2)).customize(jwtEncodingContextCaptor.capture());
		// Access Token context
		JwtEncodingContext accessTokenContext = jwtEncodingContextCaptor.getAllValues().get(0);
		assertThat(accessTokenContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(accessTokenContext.<Authentication>getPrincipal()).isEqualTo(authorization.getAttribute(Principal.class.getName()));
		assertThat(accessTokenContext.getAuthorization()).isEqualTo(authorization);
		assertThat(accessTokenContext.getAuthorizedScopes())
				.isEqualTo(authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME));
		assertThat(accessTokenContext.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(accessTokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.REFRESH_TOKEN);
		assertThat(accessTokenContext.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant()).isEqualTo(authentication);
		assertThat(accessTokenContext.getHeaders()).isNotNull();
		assertThat(accessTokenContext.getClaims()).isNotNull();
		Map<String, Object> claims = new HashMap<>();
		accessTokenContext.getClaims().claims(claims::putAll);
		assertThat(claims).flatExtracting(OAuth2ParameterNames.SCOPE)
				.containsExactlyInAnyOrder(OidcScopes.OPENID, "scope1");
		// ID Token context
		JwtEncodingContext idTokenContext = jwtEncodingContextCaptor.getAllValues().get(1);
		assertThat(idTokenContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(idTokenContext.<Authentication>getPrincipal()).isEqualTo(authorization.getAttribute(Principal.class.getName()));
		assertThat(idTokenContext.getAuthorization()).isEqualTo(authorization);
		assertThat(idTokenContext.getAuthorizedScopes())
				.isEqualTo(authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME));
		assertThat(idTokenContext.getTokenType().getValue()).isEqualTo(OidcParameterNames.ID_TOKEN);
		assertThat(idTokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.REFRESH_TOKEN);
		assertThat(idTokenContext.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant()).isEqualTo(authentication);
		assertThat(idTokenContext.getHeaders()).isNotNull();
		assertThat(idTokenContext.getClaims()).isNotNull();

		verify(this.jwtEncoder, times(2)).encode(any(), any());		// Access token and ID Token

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getRegisteredClient().getId()).isEqualTo(updatedAuthorization.getRegisteredClientId());
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(accessTokenAuthentication.getAccessToken()).isEqualTo(updatedAuthorization.getAccessToken().getToken());
		assertThat(updatedAuthorization.getAccessToken()).isNotEqualTo(authorization.getAccessToken());
		OAuth2Authorization.Token<OidcIdToken> idToken = updatedAuthorization.getToken(OidcIdToken.class);
		assertThat(idToken).isNotNull();
		assertThat(accessTokenAuthentication.getAdditionalParameters())
				.containsExactly(entry(OidcParameterNames.ID_TOKEN, idToken.getToken().getTokenValue()));
		assertThat(accessTokenAuthentication.getRefreshToken()).isEqualTo(updatedAuthorization.getRefreshToken().getToken());
		// By default, refresh token is reused
		assertThat(updatedAuthorization.getRefreshToken()).isEqualTo(authorization.getRefreshToken());
	}

	@Test
	public void authenticateWhenReuseRefreshTokensFalseThenReturnNewRefreshToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.tokenSettings(tokenSettings -> tokenSettings.reuseRefreshTokens(false))
				.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getRefreshToken()).isEqualTo(updatedAuthorization.getRefreshToken().getToken());
		assertThat(updatedAuthorization.getRefreshToken()).isNotEqualTo(authorization.getRefreshToken());
	}

	@Test
	public void authenticateWhenRequestedScopesAuthorizedThenAccessTokenIncludesScopes() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scope("scope2")
				.scope("scope3")
				.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		Set<String> authorizedScopes = authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME);
		Set<String> requestedScopes = new HashSet<>(authorizedScopes);
		requestedScopes.remove("scope1");
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, requestedScopes, null);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		assertThat(accessTokenAuthentication.getAccessToken().getScopes()).isEqualTo(requestedScopes);
	}

	@Test
	public void authenticateWhenRequestedScopesNotAuthorizedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		Set<String> authorizedScopes = authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME);
		Set<String> requestedScopes = new HashSet<>(authorizedScopes);
		requestedScopes.add("unauthorized");
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, requestedScopes, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
	}

	@Test
	public void authenticateWhenInvalidRefreshTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				"invalid", clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotOAuth2ClientAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				"refresh-token", clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret(), ClientAuthenticationMethod.BASIC, null);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				"refresh-token", clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenRefreshTokenIssuedToAnotherClientThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				TestRegisteredClients.registeredClient2().build());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientNotAuthorizedToRefreshTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantTypes(grantTypes -> grantTypes.remove(AuthorizationGrantType.REFRESH_TOKEN))
				.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
	}

	@Test
	public void authenticateWhenExpiredRefreshTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2RefreshToken expiredRefreshToken = new OAuth2RefreshToken2(
				"expired-refresh-token", Instant.now().minusSeconds(120), Instant.now().minusSeconds(60));
		authorization = OAuth2Authorization.from(authorization).token(expiredRefreshToken).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenRevokedRefreshTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken2(
				"refresh-token", Instant.now().minusSeconds(120), Instant.now().plusSeconds(1000));
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(refreshToken, (metadata) -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true))
				.build();
		when(this.authorizationService.findByToken(
				eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenClientIsPublicThenIssueReducedRefreshToken() {
		Duration refreshTokenTimeToLive = Duration.ofHours(24);
		Duration currentTokenDisuseDuration = Duration.ofHours(1);
		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient()
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.tokenSettings(tokenSettings -> {
					tokenSettings.reuseRefreshTokens(false);
					tokenSettings.refreshTokenTimeToLive(refreshTokenTimeToLive);
				})
				.build();
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken2("refresh-token",
				Instant.now().minus(currentTokenDisuseDuration), Instant.now().plus(refreshTokenTimeToLive));
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(refreshToken)
				.build();
		when(this.authorizationService.findByToken(
				eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		OAuth2AccessTokenAuthenticationToken authenticationToken = (OAuth2AccessTokenAuthenticationToken)
				this.authenticationProvider.authenticate(authentication);

		assertThat(authenticationToken.getRefreshToken()).isNotNull();
		assertThat(authenticationToken.getRefreshToken().getExpiresAt())
				.isNotNull()
				.isBeforeOrEqualTo(Instant.now().plus(refreshTokenTimeToLive.minus(currentTokenDisuseDuration)));
	}

	@Test
	public void authenticateWhenClientIsPublicAndCurrentTokenHasNotIssuedAtThenGenerateRefreshToken() {
		Duration refreshTokenTimeToLive = Duration.ofHours(24);
		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient()
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.tokenSettings(tokenSettings -> {
					tokenSettings.reuseRefreshTokens(false);
					tokenSettings.refreshTokenTimeToLive(refreshTokenTimeToLive);
				})
				.build();
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken2("refresh-token",
				null, Instant.now().plus(refreshTokenTimeToLive));
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(refreshToken)
				.build();
		when(this.authorizationService.findByToken(
				eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		OAuth2AccessTokenAuthenticationToken authenticationToken = (OAuth2AccessTokenAuthenticationToken)
				this.authenticationProvider.authenticate(authentication);

		assertThat(authenticationToken.getRefreshToken()).isNotNull();
		assertThat(authenticationToken.getRefreshToken().getExpiresAt())
				.isNotNull()
				.isBeforeOrEqualTo(Instant.now().plus(refreshTokenTimeToLive));
	}

	private static Jwt createJwt(Set<String> scope) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
		return Jwt.withTokenValue("refreshed-access-token")
				.header(JoseHeaderNames.ALG, SignatureAlgorithm.RS256.getName())
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.claim(OAuth2ParameterNames.SCOPE, scope)
				.build();
	}
}
