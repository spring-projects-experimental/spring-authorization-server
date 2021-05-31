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

package org.springframework.security.oauth2.server.authorization.web;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod2;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAssertionAuthenticationToken;

import static org.assertj.core.api.Assertions.*;
import static org.assertj.core.api.Assertions.entry;

public class ClientAssertionAuhenticationConverterTests {

	private ClientAssertionAuthenticationConverter converter = new ClientAssertionAuthenticationConverter();

	private void shouldThrow(MockHttpServletRequest request, String errorCode) {
		assertThatThrownBy(() -> this.converter.convert(request))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(errorCode);
	}

	@Test
	public void convertWhenAuthorizationHeaderNotBasicThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenBadAssertionTypeThenThrow() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames2.CLIENT_ASSERTION_TYPE, "borken");
		shouldThrow(request, OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenNoClientAssertionThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames2.CLIENT_ASSERTION_TYPE, ClientAuthenticationMethod2.JWT.getValue());
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMultipleAssertionsThenThrow() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames2.CLIENT_ASSERTION_TYPE, ClientAuthenticationMethod2.JWT.getValue());
		request.addParameter(OAuth2ParameterNames2.CLIENT_ASSERTION, "some_jwt_assertion");
		request.addParameter(OAuth2ParameterNames2.CLIENT_ASSERTION, "other_jwt_assertion");
		shouldThrow(request, OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenValidAssertionJwt() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames2.CLIENT_ASSERTION_TYPE, ClientAuthenticationMethod2.JWT.getValue());
		request.addParameter(OAuth2ParameterNames2.CLIENT_ASSERTION, "some_jwt_assertion");
		OAuth2ClientAssertionAuthenticationToken authentication = (OAuth2ClientAssertionAuthenticationToken) this.converter.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getPrincipal()).isEqualTo("some_jwt_assertion");
		assertThat(authentication.getCredentials()).isEqualTo("some_jwt_assertion");
		assertThat(authentication.getClientAssertion()).isEqualTo("some_jwt_assertion");
		assertThat(authentication.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod2.JWT);
	}

	@Test
	public void convertWhenConfidentialClientWithPkceParametersThenAdditionalParametersIncluded() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(PkceParameterNames.CODE_VERIFIER, "code-verifier-1");
		request.addParameter(OAuth2ParameterNames2.CLIENT_ASSERTION_TYPE, ClientAuthenticationMethod2.JWT.getValue());
		request.addParameter(OAuth2ParameterNames2.CLIENT_ASSERTION, "some_jwt_assertion");
		OAuth2ClientAssertionAuthenticationToken authentication = (OAuth2ClientAssertionAuthenticationToken) this.converter.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getPrincipal()).isEqualTo("some_jwt_assertion");
		assertThat(authentication.getCredentials()).isEqualTo("some_jwt_assertion");
		assertThat(authentication.getClientAssertion()).isEqualTo("some_jwt_assertion");
		assertThat(authentication.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod2.JWT);
		assertThat(authentication.getAdditionalParameters())
				.containsOnly(
						entry(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
						entry(OAuth2ParameterNames.CODE, "code"),
						entry(PkceParameterNames.CODE_VERIFIER, "code-verifier-1"));
	}
}
