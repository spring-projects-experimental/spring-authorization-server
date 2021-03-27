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

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Converts Jwt to Registered client, yet as this is not necessarily stateless (typically uses
 * {@link RegisteredClientRepository}), we don't use {@link org.springframework.core.convert.converter.Converter}
 * interface here.
 *
 * @author Rafal Lewczuk
 * @since 0.1.2
 */
@FunctionalInterface
public interface JwtToRegisteredClientResolver {

	/**
	 * Looks for registered client based on JWT token
	 *
	 * @param jwt parsed JWT token
	 * @return registered client or {@code null} if nothing matches
	 */
	RegisteredClient resolve(Jwt jwt);

}
