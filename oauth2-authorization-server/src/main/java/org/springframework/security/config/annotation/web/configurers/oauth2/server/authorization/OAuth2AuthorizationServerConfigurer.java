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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import java.net.URI;
import java.util.Map;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwsEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientJwtAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.DefaultJwtToRegisteredClientResolver;
import org.springframework.security.oauth2.server.authorization.client.JwtToRegisteredClientResolver;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcClientRegistrationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.NimbusJwkSetEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationServerMetadataEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenRevocationEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Gerardo Roza
 * @author Ovidiu Popa
 * @since 0.0.1
 * @see AbstractHttpConfigurer
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationEndpointFilter
 * @see OAuth2TokenEndpointFilter
 * @see OAuth2TokenIntrospectionEndpointFilter
 * @see OAuth2TokenRevocationEndpointFilter
 * @see NimbusJwkSetEndpointFilter
 * @see OidcProviderConfigurationEndpointFilter
 * @see OAuth2AuthorizationServerMetadataEndpointFilter
 * @see OAuth2ClientAuthenticationFilter
 * @see OidcClientRegistrationEndpointFilter
 */
public final class OAuth2AuthorizationServerConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OAuth2AuthorizationServerConfigurer<B>, B> {

	private RequestMatcher authorizationEndpointMatcher;
	private RequestMatcher tokenEndpointMatcher;
	private RequestMatcher tokenIntrospectionEndpointMatcher;
	private RequestMatcher tokenRevocationEndpointMatcher;
	private RequestMatcher jwkSetEndpointMatcher;
	private RequestMatcher oidcProviderConfigurationEndpointMatcher;
	private RequestMatcher authorizationServerMetadataEndpointMatcher;
	private RequestMatcher oidcClientRegistrationEndpointMatcher;
	private final RequestMatcher endpointsMatcher = (request) ->
			this.authorizationEndpointMatcher.matches(request) ||
			this.tokenEndpointMatcher.matches(request) ||
			this.tokenIntrospectionEndpointMatcher.matches(request) ||
			this.tokenRevocationEndpointMatcher.matches(request) ||
			this.jwkSetEndpointMatcher.matches(request) ||
			this.oidcProviderConfigurationEndpointMatcher.matches(request) ||
			this.authorizationServerMetadataEndpointMatcher.matches(request) ||
			this.oidcClientRegistrationEndpointMatcher.matches(request);

	/**
	 * Sets the repository of registered clients.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> registeredClientRepository(RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.getBuilder().setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
		return this;
	}

	/**
	 * Sets the authorization service.
	 *
	 * @param authorizationService the authorization service
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> authorizationService(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.getBuilder().setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		return this;
	}

	/**
	 * Sets the provider settings.
	 *
	 * @param providerSettings the provider settings
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> providerSettings(ProviderSettings providerSettings) {
		Assert.notNull(providerSettings, "providerSettings cannot be null");
		this.getBuilder().setSharedObject(ProviderSettings.class, providerSettings);
		return this;
	}

	/**
	 * Returns a {@link RequestMatcher} for the authorization server endpoints.
	 *
	 * @return a {@link RequestMatcher} for the authorization server endpoints
	 */
	public RequestMatcher getEndpointsMatcher() {
		return this.endpointsMatcher;
	}

	@Override
	public void init(B builder) {
		ProviderSettings providerSettings = getProviderSettings(builder);
		validateProviderSettings(providerSettings);
		initEndpointMatchers(providerSettings);

		OAuth2ClientAuthenticationProvider clientAuthenticationProvider =
				new OAuth2ClientAuthenticationProvider(
						getRegisteredClientRepository(builder),
						getAuthorizationService(builder));

		PasswordEncoder passwordEncoder = getOptionalBean(builder, PasswordEncoder.class);
		if (passwordEncoder != null) {
			clientAuthenticationProvider.setPasswordEncoder(passwordEncoder);
		}
		builder.authenticationProvider(postProcess(clientAuthenticationProvider));

		JwtDecoder jwtDecoder = getJwtDecoder(builder);
		if (jwtDecoder != null) {
			OAuth2ClientJwtAuthenticationProvider clientJwtAuthenticationProvider =
					new OAuth2ClientJwtAuthenticationProvider(
							getJwtToRegisteredClientResolver(builder),
							getAuthorizationService(builder),
							jwtDecoder);
			builder.authenticationProvider(postProcess(clientJwtAuthenticationProvider));
		}

		JwtEncoder jwtEncoder = getJwtEncoder(builder);
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = getJwtCustomizer(builder);

		OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider =
				new OAuth2AuthorizationCodeAuthenticationProvider(
						getAuthorizationService(builder),
						jwtEncoder);
		if (jwtCustomizer != null) {
			authorizationCodeAuthenticationProvider.setJwtCustomizer(jwtCustomizer);
		}
		builder.authenticationProvider(postProcess(authorizationCodeAuthenticationProvider));

		OAuth2RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider =
				new OAuth2RefreshTokenAuthenticationProvider(
						getAuthorizationService(builder),
						jwtEncoder);
		if (jwtCustomizer != null) {
			refreshTokenAuthenticationProvider.setJwtCustomizer(jwtCustomizer);
		}
		builder.authenticationProvider(postProcess(refreshTokenAuthenticationProvider));

		OAuth2ClientCredentialsAuthenticationProvider clientCredentialsAuthenticationProvider =
				new OAuth2ClientCredentialsAuthenticationProvider(
						getAuthorizationService(builder),
						jwtEncoder);
		if (jwtCustomizer != null) {
			clientCredentialsAuthenticationProvider.setJwtCustomizer(jwtCustomizer);
		}
		builder.authenticationProvider(postProcess(clientCredentialsAuthenticationProvider));

		OAuth2TokenIntrospectionAuthenticationProvider tokenIntrospectionAuthenticationProvider =
				new OAuth2TokenIntrospectionAuthenticationProvider(
						getRegisteredClientRepository(builder),
						getAuthorizationService(builder));
		builder.authenticationProvider(postProcess(tokenIntrospectionAuthenticationProvider));

		OAuth2TokenRevocationAuthenticationProvider tokenRevocationAuthenticationProvider =
				new OAuth2TokenRevocationAuthenticationProvider(
						getAuthorizationService(builder));
		builder.authenticationProvider(postProcess(tokenRevocationAuthenticationProvider));

		// TODO Make OpenID Client Registration an "opt-in" feature
		OidcClientRegistrationAuthenticationProvider oidcClientRegistrationAuthenticationProvider =
				new OidcClientRegistrationAuthenticationProvider(
						getRegisteredClientRepository(builder),
						getAuthorizationService(builder));
		builder.authenticationProvider(postProcess(oidcClientRegistrationAuthenticationProvider));

		ExceptionHandlingConfigurer<B> exceptionHandling = builder.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling != null) {
			exceptionHandling.defaultAuthenticationEntryPointFor(
					new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
					new OrRequestMatcher(
							this.tokenEndpointMatcher,
							this.tokenIntrospectionEndpointMatcher,
							this.tokenRevocationEndpointMatcher)
			);
		}
	}

	@Override
	public void configure(B builder) {
		ProviderSettings providerSettings = getProviderSettings(builder);
		if (providerSettings.issuer() != null) {
			OidcProviderConfigurationEndpointFilter oidcProviderConfigurationEndpointFilter =
					new OidcProviderConfigurationEndpointFilter(providerSettings);
			builder.addFilterBefore(postProcess(oidcProviderConfigurationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

			OAuth2AuthorizationServerMetadataEndpointFilter authorizationServerMetadataEndpointFilter =
					new OAuth2AuthorizationServerMetadataEndpointFilter(providerSettings);
			builder.addFilterBefore(postProcess(authorizationServerMetadataEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
		}

		JWKSource<SecurityContext> jwkSource = getJwkSource(builder);
		NimbusJwkSetEndpointFilter jwkSetEndpointFilter = new NimbusJwkSetEndpointFilter(
				jwkSource,
				providerSettings.jwkSetEndpoint());
		builder.addFilterBefore(postProcess(jwkSetEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

		OAuth2ClientAuthenticationFilter clientAuthenticationFilter =
				new OAuth2ClientAuthenticationFilter(
						authenticationManager,
						new OrRequestMatcher(
								this.tokenEndpointMatcher,
								this.tokenIntrospectionEndpointMatcher,
								this.tokenRevocationEndpointMatcher));
		builder.addFilterAfter(postProcess(clientAuthenticationFilter), AbstractPreAuthenticatedProcessingFilter.class);

		OAuth2AuthorizationEndpointFilter authorizationEndpointFilter =
				new OAuth2AuthorizationEndpointFilter(
						getRegisteredClientRepository(builder),
						getAuthorizationService(builder),
						providerSettings.authorizationEndpoint());
		builder.addFilterBefore(postProcess(authorizationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

		OAuth2TokenEndpointFilter tokenEndpointFilter =
				new OAuth2TokenEndpointFilter(
						authenticationManager,
						providerSettings.tokenEndpoint());
		builder.addFilterAfter(postProcess(tokenEndpointFilter), FilterSecurityInterceptor.class);

		OAuth2TokenIntrospectionEndpointFilter tokenIntrospectionEndpointFilter =
				new OAuth2TokenIntrospectionEndpointFilter(
						authenticationManager,
						providerSettings.tokenIntrospectionEndpoint());
		builder.addFilterAfter(postProcess(tokenIntrospectionEndpointFilter), OAuth2TokenEndpointFilter.class);

		OAuth2TokenRevocationEndpointFilter tokenRevocationEndpointFilter =
				new OAuth2TokenRevocationEndpointFilter(
						authenticationManager,
						providerSettings.tokenRevocationEndpoint());
		builder.addFilterAfter(postProcess(tokenRevocationEndpointFilter), OAuth2TokenIntrospectionEndpointFilter.class);

		// TODO Make OpenID Client Registration an "opt-in" feature
		OidcClientRegistrationEndpointFilter oidcClientRegistrationEndpointFilter =
				new OidcClientRegistrationEndpointFilter(
						authenticationManager,
						providerSettings.oidcClientRegistrationEndpoint());
		builder.addFilterAfter(postProcess(oidcClientRegistrationEndpointFilter), OAuth2TokenRevocationEndpointFilter.class);
	}

	private void initEndpointMatchers(ProviderSettings providerSettings) {
		this.authorizationEndpointMatcher = new OrRequestMatcher(
				new AntPathRequestMatcher(
						providerSettings.authorizationEndpoint(),
						HttpMethod.GET.name()),
				new AntPathRequestMatcher(
						providerSettings.authorizationEndpoint(),
						HttpMethod.POST.name()));
		this.tokenEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.tokenEndpoint(), HttpMethod.POST.name());
		this.tokenIntrospectionEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.tokenIntrospectionEndpoint(), HttpMethod.POST.name());
		this.tokenRevocationEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.tokenRevocationEndpoint(), HttpMethod.POST.name());
		this.jwkSetEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.jwkSetEndpoint(), HttpMethod.GET.name());
		this.oidcProviderConfigurationEndpointMatcher = new AntPathRequestMatcher(
				OidcProviderConfigurationEndpointFilter.DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI, HttpMethod.GET.name());
		this.authorizationServerMetadataEndpointMatcher = new AntPathRequestMatcher(
				OAuth2AuthorizationServerMetadataEndpointFilter.DEFAULT_OAUTH2_AUTHORIZATION_SERVER_METADATA_ENDPOINT_URI, HttpMethod.GET.name());
		this.oidcClientRegistrationEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.oidcClientRegistrationEndpoint(), HttpMethod.POST.name());
	}

	private static void validateProviderSettings(ProviderSettings providerSettings) {
		if (providerSettings.issuer() != null) {
			try {
				new URI(providerSettings.issuer()).toURL();
			} catch (Exception ex) {
				throw new IllegalArgumentException("issuer must be a valid URL", ex);
			}
		}
	}

	private static <B extends HttpSecurityBuilder<B>> RegisteredClientRepository getRegisteredClientRepository(B builder) {
		RegisteredClientRepository registeredClientRepository = builder.getSharedObject(RegisteredClientRepository.class);
		if (registeredClientRepository == null) {
			registeredClientRepository = getBean(builder, RegisteredClientRepository.class);
			builder.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
		}
		return registeredClientRepository;
	}

	private static <B extends HttpSecurityBuilder<B>> JwtToRegisteredClientResolver getJwtToRegisteredClientResolver(B builder) {
		JwtToRegisteredClientResolver resolver = builder.getSharedObject(JwtToRegisteredClientResolver.class);
		if (resolver == null) {
			try {
				resolver = builder.getSharedObject(ApplicationContext.class).getBean(JwtToRegisteredClientResolver.class);
			} catch (NoSuchBeanDefinitionException e) {
				resolver = new DefaultJwtToRegisteredClientResolver(getRegisteredClientRepository(builder));
			}
			builder.setSharedObject(JwtToRegisteredClientResolver.class, resolver);
		}
		return resolver;
	}

	private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationService getAuthorizationService(B builder) {
		OAuth2AuthorizationService authorizationService = builder.getSharedObject(OAuth2AuthorizationService.class);
		if (authorizationService == null) {
			authorizationService = getOptionalBean(builder, OAuth2AuthorizationService.class);
			if (authorizationService == null) {
				authorizationService = new InMemoryOAuth2AuthorizationService();
			}
			builder.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		}
		return authorizationService;
	}

	private static <B extends HttpSecurityBuilder<B>>JwtDecoder getJwtDecoder(B builder) {
		JwtDecoder jwtDecoder = builder.getSharedObject(JwtDecoder.class);
		if (jwtDecoder == null) {
			jwtDecoder = getOptionalBean(builder, JwtDecoder.class);
		}
		return jwtDecoder;
	}

	private static <B extends HttpSecurityBuilder<B>> JwtEncoder getJwtEncoder(B builder) {
		JwtEncoder jwtEncoder = builder.getSharedObject(JwtEncoder.class);
		if (jwtEncoder == null) {
			jwtEncoder = getOptionalBean(builder, JwtEncoder.class);
			if (jwtEncoder == null) {
				JWKSource<SecurityContext> jwkSource = getJwkSource(builder);
				jwtEncoder = new NimbusJwsEncoder(jwkSource);
			}
			builder.setSharedObject(JwtEncoder.class, jwtEncoder);
		}
		return jwtEncoder;
	}

	@SuppressWarnings("unchecked")
	private static <B extends HttpSecurityBuilder<B>> JWKSource<SecurityContext> getJwkSource(B builder) {
		JWKSource<SecurityContext> jwkSource = builder.getSharedObject(JWKSource.class);
		if (jwkSource == null) {
			ResolvableType type = ResolvableType.forClassWithGenerics(JWKSource.class, SecurityContext.class);
			jwkSource = getBean(builder, type);
			builder.setSharedObject(JWKSource.class, jwkSource);
		}
		return jwkSource;
	}

	@SuppressWarnings("unchecked")
	private static <B extends HttpSecurityBuilder<B>> OAuth2TokenCustomizer<JwtEncodingContext> getJwtCustomizer(B builder) {
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = builder.getSharedObject(OAuth2TokenCustomizer.class);
		if (jwtCustomizer == null) {
			ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class, JwtEncodingContext.class);
			jwtCustomizer = getOptionalBean(builder, type);
			if (jwtCustomizer != null) {
				builder.setSharedObject(OAuth2TokenCustomizer.class, jwtCustomizer);
			}
		}
		return jwtCustomizer;
	}

	private static <B extends HttpSecurityBuilder<B>> ProviderSettings getProviderSettings(B builder) {
		ProviderSettings providerSettings = builder.getSharedObject(ProviderSettings.class);
		if (providerSettings == null) {
			providerSettings = getOptionalBean(builder, ProviderSettings.class);
			if (providerSettings == null) {
				providerSettings = new ProviderSettings();
			}
			builder.setSharedObject(ProviderSettings.class, providerSettings);
		}
		return providerSettings;
	}

	private static <B extends HttpSecurityBuilder<B>, T> T getBean(B builder, Class<T> type) {
		return builder.getSharedObject(ApplicationContext.class).getBean(type);
	}

	@SuppressWarnings("unchecked")
	private static <B extends HttpSecurityBuilder<B>, T> T getBean(B builder, ResolvableType type) {
		ApplicationContext context = builder.getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(type);
		if (names.length == 1) {
			return (T) context.getBean(names[0]);
		}
		if (names.length > 1) {
			throw new NoUniqueBeanDefinitionException(type, names);
		}
		throw new NoSuchBeanDefinitionException(type);
	}

	private static <B extends HttpSecurityBuilder<B>, T> T getOptionalBean(B builder, Class<T> type) {
		Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
				builder.getSharedObject(ApplicationContext.class), type);
		if (beansMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
					"Expected single matching bean of type '" + type.getName() + "' but found " +
							beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
		}
		return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
	}

	@SuppressWarnings("unchecked")
	private static <B extends HttpSecurityBuilder<B>, T> T getOptionalBean(B builder, ResolvableType type) {
		ApplicationContext context = builder.getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(type);
		if (names.length > 1) {
			throw new NoUniqueBeanDefinitionException(type, names);
		}
		return names.length == 1 ? (T) context.getBean(names[0]) : null;
	}
}
