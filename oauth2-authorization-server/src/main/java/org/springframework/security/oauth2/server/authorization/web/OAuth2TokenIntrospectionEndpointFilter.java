/*
 * Copyright 2020 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.web;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2;
import org.springframework.security.oauth2.core.endpoint.OAuth2TokenIntrospectionResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.introspection.http.converter.OAuth2TokenIntrospectionResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;

/**
 * A {@code Filter} for the OAuth 2.0 Token Introspection endpoint.
 *
 * @author Gerardo Roza
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2">Section 2 - Introspection Endpoint</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.1">Section 2.1 - Introspection Request</a>
 * @since 0.1.1
 */
public class OAuth2TokenIntrospectionEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for token introspection requests.
	 */
	public static final String DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI = "/oauth2/introspect";

	private final AuthenticationManager authenticationManager;
	private final RequestMatcher tokenEndpointMatcher;
	private final Converter<HttpServletRequest, Authentication> tokenIntrospectionAuthenticationConverter = new DefaultTokenIntrospectionAuthenticationConverter();
	private final HttpMessageConverter<OAuth2TokenIntrospectionResponse> tokenIntrospectionHttpResponseConverter = new OAuth2TokenIntrospectionResponseHttpMessageConverter();

	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2TokenIntrospectionEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param tokenIntrospectionEndpointUri the endpoint {@code URI} for token introspection requests
	 */
	public OAuth2TokenIntrospectionEndpointFilter(AuthenticationManager authenticationManager,
			String tokenIntrospectionEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(tokenIntrospectionEndpointUri, "tokenIntrospectionEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.tokenEndpointMatcher = new AntPathRequestMatcher(tokenIntrospectionEndpointUri, HttpMethod.POST.name());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.tokenEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {

			OAuth2TokenIntrospectionAuthenticationToken introspectionTokenAuthentication = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationManager
					.authenticate(this.tokenIntrospectionAuthenticationConverter.convert(request));

			OAuth2TokenIntrospectionResponse tokenIntrospectionResponse = introspectionTokenAuthentication
					.isTokenActive()
							? generateTokenIntrospectionResponse(
									introspectionTokenAuthentication.getTokenHolder(),
									introspectionTokenAuthentication.getClientId())
							: OAuth2TokenIntrospectionResponse.builder(false).build();

			this.sendTokenIntrospectionResponse(response, tokenIntrospectionResponse);
		} catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			sendErrorResponse(response, ex.getError());
		}
	}

	private OAuth2TokenIntrospectionResponse generateTokenIntrospectionResponse(
			Token<? extends AbstractOAuth2Token> tokenHolder, String clientId) {
		AbstractOAuth2Token token = tokenHolder.getToken();
		OAuth2TokenIntrospectionResponse.Builder builder = OAuth2TokenIntrospectionResponse
				.withClaims(tokenHolder.getClaims());
		builder.active(true).clientId(clientId);
		Optional.ofNullable(token.getIssuedAt()).ifPresent(builder::issuedAt);
		Optional.ofNullable(token.getExpiresAt()).ifPresent(builder::expirationTime);
		TokenToIntrospectionResponseFieldsMapper.extractFromToken(token, builder);
		return builder.build();
	}

	private void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}

	private void sendTokenIntrospectionResponse(HttpServletResponse response,
			OAuth2TokenIntrospectionResponse tokenIntrospectionResponse) throws IOException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.tokenIntrospectionHttpResponseConverter.write(tokenIntrospectionResponse, null, httpResponse);
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(
				errorCode, "OAuth 2.0 Token Introspection Parameter: " + parameterName,
				"https://tools.ietf.org/html/rfc7662#section-2.1");
		throw new OAuth2AuthenticationException(error);
	}

	/**
	 * Mapper that helps populate {@code OAuth2TokenIntrospectionResponse} fields from different {@code AbstractOAuth2Token}
	 * implementations.
	 *
	 * @see OAuth2AccessToken
	 *
	 * @author Gerardo Roza
	 */
	private static final class TokenToIntrospectionResponseFieldsMapper {

		private static final Map<Class<? extends AbstractOAuth2Token>, BiConsumer<AbstractOAuth2Token, OAuth2TokenIntrospectionResponse.Builder>> supportedTokens;
		static {
			Map<Class<? extends AbstractOAuth2Token>, BiConsumer<AbstractOAuth2Token, OAuth2TokenIntrospectionResponse.Builder>> tokenMap = new HashMap<>();
			tokenMap.put(
					OAuth2AccessToken.class,
					(token, builder) -> extractFromOAuth2AccessToken((OAuth2AccessToken) token, builder));
			supportedTokens = Collections.unmodifiableMap(tokenMap);
		}

		private TokenToIntrospectionResponseFieldsMapper() {
		}

		/**
		 * Extracts all the corresponding fields from an {@code OAuth2AccessToken}.
		 *
		 * @param scope The token scope, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		private static OAuth2TokenIntrospectionResponse.Builder extractFromOAuth2AccessToken(
				final OAuth2AccessToken accessToken, OAuth2TokenIntrospectionResponse.Builder builder) {
			Collection<String> scopes = accessToken.getScopes();
			if (!scopes.isEmpty()) {
				builder.scope(String.join(" ", scopes));
			}
			builder.tokenType(OAuth2AccessToken.TokenType.BEARER);
			return builder;
		}

		/**
		 * Extracts all the corresponding fields from an {@code OAuth2AccessToken}.
		 *
		 * @param scope The token scope, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public static OAuth2TokenIntrospectionResponse.Builder extractFromToken(final AbstractOAuth2Token token,
				OAuth2TokenIntrospectionResponse.Builder builder) {
			Optional.ofNullable(supportedTokens.get(token.getClass()))
					.ifPresent(consumer -> consumer.accept(token, builder));
			return builder;
		}
	}

	private static class DefaultTokenIntrospectionAuthenticationConverter
			implements Converter<HttpServletRequest, Authentication> {

		@Override
		public Authentication convert(HttpServletRequest request) {
			Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

			MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

			// token (REQUIRED)
			String token = parameters.getFirst(OAuth2ParameterNames2.TOKEN);
			if (!StringUtils.hasText(token) || parameters.get(OAuth2ParameterNames2.TOKEN).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames2.TOKEN);
			}

			// token_type_hint (OPTIONAL)
			String tokenTypeHint = parameters.getFirst(OAuth2ParameterNames2.TOKEN_TYPE_HINT);
			if (StringUtils.hasText(tokenTypeHint)
					&& parameters.get(OAuth2ParameterNames2.TOKEN_TYPE_HINT).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames2.TOKEN_TYPE_HINT);
			}

			return new OAuth2TokenIntrospectionAuthenticationToken(token, clientPrincipal, tokenTypeHint);
		}
	}
}
