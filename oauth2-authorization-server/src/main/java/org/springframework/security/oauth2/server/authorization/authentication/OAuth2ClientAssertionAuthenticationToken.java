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

package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.Version;

import java.util.Collections;
import java.util.Map;

/**
 * Represents client authentication token bearing client assertion (either JWT or SAML2)
 *
 * @author Rafal Lewczuk
 * @since 0.1.2
 */
public class OAuth2ClientAssertionAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

	private final String clientAssertion;
	private final Map<String, Object> additionalParameters;
	private final ClientAuthenticationMethod clientAuthenticationMethod;


	public OAuth2ClientAssertionAuthenticationToken(String clientAssertion,
			ClientAuthenticationMethod clientAuthenticationMethod, Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		this.clientAssertion = clientAssertion;
		this.additionalParameters = additionalParameters;
		this.clientAuthenticationMethod = clientAuthenticationMethod;
	}

	@Override
	public Object getCredentials() {
		return clientAssertion;
	}

	@Override
	public Object getPrincipal() {
		return clientAssertion; // TODO what's here ? Do we need separate classes for various assertion types and extract subject name here ?
	}

	/**
	 * Returns the additional parameters
	 *
	 * @return the additional parameters
	 */
	public @Nullable
	Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	public ClientAuthenticationMethod getClientAuthenticationMethod() {
		return clientAuthenticationMethod;
	}

	/**
	 * Returns client assertion in its compact form (String)
	 *
	 * @return client assertion
	 */
	public String getClientAssertion() {
		return clientAssertion;
	}

}
