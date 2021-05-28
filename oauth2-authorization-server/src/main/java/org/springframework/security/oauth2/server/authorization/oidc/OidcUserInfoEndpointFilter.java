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
package org.springframework.security.oauth2.server.authorization.oidc;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.http.converter.OidcUserInfoHttpMessageConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * A {@code Filter} that processes OpenID User Info requests.
 *
 * @author Ido Salomon
 * @see OidcUserInfo
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest">5.3.1. UserInfo Request</a>
 * @since 0.1.1
 */
public class OidcUserInfoEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for OpenID User Info requests.
	 */
	public static final String DEFAULT_OIDC_USER_INFO_ENDPOINT_URI = "/userinfo";

	private final RequestMatcher requestMatcher;
	private final OidcUserInfoHttpMessageConverter oidcUserInfoHttpMessageConverter =
			new OidcUserInfoHttpMessageConverter();
	private final UserInfoClaimsMapper userInfoClaimsMapper;

	public OidcUserInfoEndpointFilter(UserInfoClaimsMapper userInfoClaimsMapper) {
		AntPathRequestMatcher userInfoGetMatcher = new AntPathRequestMatcher(
				DEFAULT_OIDC_USER_INFO_ENDPOINT_URI,
				HttpMethod.GET.name()
		);
		AntPathRequestMatcher userInfoPostMatcher = new AntPathRequestMatcher(
				DEFAULT_OIDC_USER_INFO_ENDPOINT_URI,
				HttpMethod.POST.name()
		);
		this.requestMatcher = new OrRequestMatcher(userInfoGetMatcher, userInfoPostMatcher);
		this.userInfoClaimsMapper = userInfoClaimsMapper;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		Object authenticationDetails = authentication.getDetails();
		Object principal = authentication.getPrincipal();
		OidcUserInfo oidcUserInfo = userInfoClaimsMapper.map(principal);

		if (authenticationDetails instanceof OAuth2AccessToken) {
			oidcUserInfo = getUserInfoClaimsRequestedByScope(oidcUserInfo, ((OAuth2AccessToken) authenticationDetails).getScopes());
		} else {
			oidcUserInfo = OidcUserInfo.builder()
					.subject(oidcUserInfo.getSubject())
					.build();
		}

		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.oidcUserInfoHttpMessageConverter.write(
				oidcUserInfo, MediaType.APPLICATION_JSON, httpResponse);
	}

	private OidcUserInfo getUserInfoClaimsRequestedByScope(OidcUserInfo userInfo, Set<String> scopes) {
		Set<String> scopeRequestedClaimNames = getScopeRequestedClaimNames(scopes);

		Map<String, Object> scopeRequestedClaims = userInfo.getClaims().entrySet().stream()
				.filter(claim -> scopeRequestedClaimNames.contains(claim.getKey()))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

		return new OidcUserInfo(scopeRequestedClaims);
	}

	private Set<String> getScopeRequestedClaimNames(Set<String> scopes) {
		Set<String> scopeRequestedClaimNames = new HashSet<>(Arrays.asList(StandardClaimNames.SUB));
		Set<String> profileClaimNames = new HashSet<>(Arrays.asList(StandardClaimNames.NAME,
				StandardClaimNames.FAMILY_NAME, StandardClaimNames.GIVEN_NAME, StandardClaimNames.MIDDLE_NAME,
				StandardClaimNames.NICKNAME, StandardClaimNames.PREFERRED_USERNAME, StandardClaimNames.PROFILE,
				StandardClaimNames.PICTURE, StandardClaimNames.WEBSITE, StandardClaimNames.GENDER,
				StandardClaimNames.BIRTHDATE, StandardClaimNames.ZONEINFO, StandardClaimNames.LOCALE, StandardClaimNames.UPDATED_AT));
		Set<String> emailClaimNames = new HashSet<>(Arrays.asList(StandardClaimNames.EMAIL, StandardClaimNames.EMAIL_VERIFIED));
		String addressClaimName = StandardClaimNames.ADDRESS;
		Set<String> phoneClaimNames = new HashSet<>(Arrays.asList(StandardClaimNames.PHONE_NUMBER, StandardClaimNames.PHONE_NUMBER_VERIFIED));

		if (scopes.contains(OidcScopes.ADDRESS)) {
			scopeRequestedClaimNames.add(addressClaimName);
		}
		if (scopes.contains(OidcScopes.EMAIL)) {
			scopeRequestedClaimNames.addAll(emailClaimNames);
		}
		if (scopes.contains(OidcScopes.PHONE)) {
			scopeRequestedClaimNames.addAll(phoneClaimNames);
		}
		if (scopes.contains(OidcScopes.PROFILE)) {
			scopeRequestedClaimNames.addAll(profileClaimNames);
		}

		return scopeRequestedClaimNames;
	}

}
