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
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken2;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Refresh Token Grant.
 *
 * @author Alexey Nesterov
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @since 0.0.3
 * @see OAuth2RefreshTokenAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see JwtEncoder
 * @see OAuth2TokenCustomizer
 * @see JwtEncodingContext
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.5">Section 1.5 Refresh Token Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-6">Section 6 Refreshing an Access Token</a>
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-07#section-8">Section 8 Refresh Tokens</a>
 */
public class OAuth2RefreshTokenAuthenticationProvider implements AuthenticationProvider {
	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);
	private static final StringKeyGenerator TOKEN_GENERATOR = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
	private final OAuth2AuthorizationService authorizationService;
	private final JwtEncoder jwtEncoder;
	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = (context) -> {};
	private ProviderSettings providerSettings;

	/**
	 * Constructs an {@code OAuth2RefreshTokenAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 */
	public OAuth2RefreshTokenAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			JwtEncoder jwtEncoder) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
		this.authorizationService = authorizationService;
		this.jwtEncoder = jwtEncoder;
	}

	public final void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
		this.jwtCustomizer = jwtCustomizer;
	}

	@Autowired(required = false)
	protected void setProviderSettings(ProviderSettings providerSettings) {
		this.providerSettings = providerSettings;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication =
				(OAuth2RefreshTokenAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal =
				getAuthenticatedClientElseThrowInvalidClient(refreshTokenAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				refreshTokenAuthentication.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}

		if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
		if (!refreshToken.isActive()) {
			// As per https://tools.ietf.org/html/rfc6749#section-5.2
			// invalid_grant: The provided authorization grant (e.g., authorization code,
			// resource owner credentials) or refresh token is invalid, expired, revoked [...].
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}

		// As per https://tools.ietf.org/html/rfc6749#section-6
		// The requested scope MUST NOT include any scope not originally granted by the resource owner,
		// and if omitted is treated as equal to the scope originally granted by the resource owner.
		Set<String> scopes = refreshTokenAuthentication.getScopes();
		Set<String> authorizedScopes = authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME);
		if (!authorizedScopes.containsAll(scopes)) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE));
		}
		if (scopes.isEmpty()) {
			scopes = authorizedScopes;
		}

		String issuer = this.providerSettings != null ? this.providerSettings.issuer() : null;

		JoseHeader.Builder headersBuilder = JwtUtils.headers();
		JwtClaimsSet.Builder claimsBuilder = JwtUtils.accessTokenClaims(
				registeredClient, issuer, authorization.getPrincipalName(), scopes);

		// @formatter:off
		JwtEncodingContext context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.authorization(authorization)
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrant(refreshTokenAuthentication)
				.build();
		// @formatter:on

		this.jwtCustomizer.customize(context);

		JoseHeader headers = context.getHeaders().build();
		JwtClaimsSet claims = context.getClaims().build();
		Jwt jwtAccessToken = this.jwtEncoder.encode(headers, claims);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwtAccessToken.getTokenValue(), jwtAccessToken.getIssuedAt(),
				jwtAccessToken.getExpiresAt(), scopes);

		TokenSettings tokenSettings = registeredClient.getTokenSettings();

		OAuth2RefreshToken currentRefreshToken = refreshToken.getToken();
		if (!tokenSettings.reuseRefreshTokens()) {
			Duration refreshTokenTimeToLive = tokenSettings.refreshTokenTimeToLive();
			boolean isPublicClient = !StringUtils.hasText(registeredClient.getClientSecret());
			if (isPublicClient) {
				// As per https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-07#section-8
				// - SHOULD rotate refresh tokens on each use, in order to be able to
				//   detect a stolen refresh token if one is replayed
				// - upon issuing a rotated refresh token, MUST NOT extend the lifetime
				//   of the new refresh token beyond the lifetime of the initial
				//   refresh token if the refresh token has a preestablished expiration time
				currentRefreshToken = generateReducedRefreshToken(refreshTokenTimeToLive,
						currentRefreshToken.getIssuedAt());
			} else {
				currentRefreshToken = generateRefreshToken(refreshTokenTimeToLive);
			}
		}

		Jwt jwtIdToken = null;
		if (authorizedScopes.contains(OidcScopes.OPENID)) {
			headersBuilder = JwtUtils.headers();
			claimsBuilder = JwtUtils.idTokenClaims(
					registeredClient, issuer, authorization.getPrincipalName(), null);

			// @formatter:off
			context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
					.registeredClient(registeredClient)
					.principal(authorization.getAttribute(Principal.class.getName()))
					.authorization(authorization)
					.authorizedScopes(authorizedScopes)
					.tokenType(ID_TOKEN_TOKEN_TYPE)
					.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
					.authorizationGrant(refreshTokenAuthentication)
					.build();
			// @formatter:on

			this.jwtCustomizer.customize(context);

			headers = context.getHeaders().build();
			claims = context.getClaims().build();
			jwtIdToken = this.jwtEncoder.encode(headers, claims);
		}

		OidcIdToken idToken;
		if (jwtIdToken != null) {
			idToken = new OidcIdToken(jwtIdToken.getTokenValue(), jwtIdToken.getIssuedAt(),
					jwtIdToken.getExpiresAt(), jwtIdToken.getClaims());
		} else {
			idToken = null;
		}

		// @formatter:off
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
				.token(accessToken,
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwtAccessToken.getClaims()))
				.refreshToken(currentRefreshToken);
		if (idToken != null) {
			authorizationBuilder
					.token(idToken,
							(metadata) ->
									metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));
		}
		authorization = authorizationBuilder.build();
		// @formatter:on

		this.authorizationService.save(authorization);

		Map<String, Object> additionalParameters = Collections.emptyMap();
		if (idToken != null) {
			additionalParameters = new HashMap<>();
			additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
		}

		return new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, currentRefreshToken, additionalParameters);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	static OAuth2RefreshToken generateRefreshToken(Duration tokenTimeToLive) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(tokenTimeToLive);
		return new OAuth2RefreshToken2(TOKEN_GENERATOR.generateKey(), issuedAt, expiresAt);
	}

	private static OAuth2RefreshToken generateReducedRefreshToken(Duration tokenTimeToLive,
			Instant currentRefreshTokenIssuedAt) {
		Duration reducedTimeToLife;
		if (currentRefreshTokenIssuedAt != null) {
			Duration currentTokenDisuseDuration = Duration.between(currentRefreshTokenIssuedAt, Instant.now());
			reducedTimeToLife = tokenTimeToLive.minus(currentTokenDisuseDuration);
		} else {
			reducedTimeToLife = tokenTimeToLive;
		}

		return generateRefreshToken(reducedTimeToLife);
	}
}
