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

package org.springframework.security.oauth2.server.authorization.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAssertionAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ClientAssertionAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		// client_assertion_type (REQUIRED)
		String clientAssertionTypeName = parameters.getFirst(OAuth2ParameterNames2.CLIENT_ASSERTION_TYPE);
		if (!StringUtils.hasText(clientAssertionTypeName)) {
			return null;
		}

		if (parameters.get(OAuth2ParameterNames2.CLIENT_ASSERTION_TYPE).size() != 1) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
		}

		ClientAuthenticationMethod clientAuthenticationMethod = null;

		if (ClientAuthenticationMethod2.JWT.getValue().equalsIgnoreCase(clientAssertionTypeName)) {
			clientAuthenticationMethod = ClientAuthenticationMethod2.JWT;
		}

		if (clientAuthenticationMethod == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
		}

		// client_assertion (REQUIRED)
		String clientAssertion = parameters.getFirst(OAuth2ParameterNames2.CLIENT_ASSERTION);
		if (!StringUtils.hasText(clientAssertion)) {
			return null;
		}

		if (parameters.get(OAuth2ParameterNames2.CLIENT_ASSERTION).size() != 1) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
		}

		return new OAuth2ClientAssertionAuthenticationToken(clientAssertion,
				clientAuthenticationMethod, extractAdditionalParameters(request));
	}

	private static Map<String, Object> extractAdditionalParameters(HttpServletRequest request) {
		Map<String, Object> additionalParameters = Collections.emptyMap();
		if (OAuth2EndpointUtils.matchesPkceTokenRequest(request)) {
			// Confidential clients can also leverage PKCE
			additionalParameters = new HashMap<>(OAuth2EndpointUtils.getParameters(request).toSingleValueMap());
			additionalParameters.remove(OAuth2ParameterNames2.CLIENT_ASSERTION);
			additionalParameters.remove(OAuth2ParameterNames2.CLIENT_ASSERTION_TYPE);
		}
		return additionalParameters;
	}

}
