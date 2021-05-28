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
package org.springframework.security.oauth2.core.oidc.http.converter;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

/**
 * A {@link HttpMessageConverter} for an {@link OidcUserInfo OIDC User Info Response}.
 *
 * @author Ido Salomon
 * @see AbstractHttpMessageConverter
 * @see OidcUserInfo
 * @since 0.1.1
 */
public class OidcUserInfoHttpMessageConverter extends AbstractHttpMessageConverter<OidcUserInfo> {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP =
			new ParameterizedTypeReference<Map<String, Object>>() {
			};

	private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

	private Converter<Map<String, Object>, OidcUserInfo> oidcUserInfoConverter = new OidcUserInfoConverter();
	private Converter<OidcUserInfo, Map<String, Object>> oidcUserInfoParametersConverter = OidcUserInfo::getClaims;

	public OidcUserInfoHttpMessageConverter() {
		super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OidcUserInfo.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OidcUserInfo readInternal(Class<? extends OidcUserInfo> clazz, HttpInputMessage inputMessage)
			throws HttpMessageNotReadableException {
		try {
			Map<String, Object> oidcUserInfoParameters =
					(Map<String, Object>) this.jsonMessageConverter.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			return this.oidcUserInfoConverter.convert(oidcUserInfoParameters);
		} catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the OIDC User Info: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(OidcUserInfo oidcUserInfo, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		try {
			Map<String, Object> oidcUserInfoResponseParameters =
					this.oidcUserInfoParametersConverter.convert(oidcUserInfo);
			this.jsonMessageConverter.write(
					oidcUserInfoResponseParameters,
					STRING_OBJECT_MAP.getType(),
					MediaType.APPLICATION_JSON,
					outputMessage
			);
		} catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the OIDC User Info response: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the OIDC User Info parameters
	 * to an {@link OidcUserInfo}.
	 *
	 * @param oidcUserInfoConverter the {@link Converter} used for converting to an
	 *                              {@link OidcUserInfo}
	 */
	public final void setOidcUserInfoConverter(Converter<Map<String, Object>, OidcUserInfo> oidcUserInfoConverter) {
		Assert.notNull(oidcUserInfoConverter, "oidcUserInfoConverter cannot be null");
		this.oidcUserInfoConverter = oidcUserInfoConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link OidcUserInfo} to a
	 * {@code Map} representation of the OIDC User Info.
	 *
	 * @param oidcUserInfoParametersConverter the {@link Converter} used for converting to a
	 *                                        {@code Map} representation of the OIDC User Info
	 */
	public final void setOidcUserInfoParametersConverter(
			Converter<OidcUserInfo, Map<String, Object>> oidcUserInfoParametersConverter) {
		Assert.notNull(oidcUserInfoParametersConverter, "oidcUserInfoParametersConverter cannot be null");
		this.oidcUserInfoParametersConverter = oidcUserInfoParametersConverter;
	}

	private static final class OidcUserInfoConverter implements Converter<Map<String, Object>, OidcUserInfo> {
		private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService.getSharedInstance();
		private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);
		private static final TypeDescriptor BOOLEAN_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Boolean.class);
		private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);
		private final ClaimTypeConverter claimTypeConverter;

		private OidcUserInfoConverter() {
			Converter<Object, ?> stringConverter = getConverter(STRING_TYPE_DESCRIPTOR);
			Converter<Object, ?> booleanConverter = getConverter(BOOLEAN_TYPE_DESCRIPTOR);

			Map<String, Converter<Object, ?>> claimConverters = new HashMap<>();
			claimConverters.put(StandardClaimNames.SUB, stringConverter);
			claimConverters.put(StandardClaimNames.PROFILE, stringConverter);
			claimConverters.put(StandardClaimNames.ADDRESS, stringConverter);
			claimConverters.put(StandardClaimNames.BIRTHDATE, stringConverter);
			claimConverters.put(StandardClaimNames.EMAIL, stringConverter);
			claimConverters.put(StandardClaimNames.EMAIL_VERIFIED, booleanConverter);
			claimConverters.put(StandardClaimNames.NAME, stringConverter);
			claimConverters.put(StandardClaimNames.GIVEN_NAME, stringConverter);
			claimConverters.put(StandardClaimNames.MIDDLE_NAME, stringConverter);
			claimConverters.put(StandardClaimNames.FAMILY_NAME, stringConverter);
			claimConverters.put(StandardClaimNames.NICKNAME, stringConverter);
			claimConverters.put(StandardClaimNames.PREFERRED_USERNAME, stringConverter);
			claimConverters.put(StandardClaimNames.LOCALE, stringConverter);
			claimConverters.put(StandardClaimNames.GENDER, stringConverter);
			claimConverters.put(StandardClaimNames.PHONE_NUMBER, stringConverter);
			claimConverters.put(StandardClaimNames.PHONE_NUMBER_VERIFIED, stringConverter);
			claimConverters.put(StandardClaimNames.PICTURE, stringConverter);
			claimConverters.put(StandardClaimNames.ZONEINFO, stringConverter);
			claimConverters.put(StandardClaimNames.WEBSITE, stringConverter);
			claimConverters.put(StandardClaimNames.UPDATED_AT, stringConverter);

			this.claimTypeConverter = new ClaimTypeConverter(claimConverters);
		}

		@Override
		public OidcUserInfo convert(Map<String, Object> source) {
			Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
			return new OidcUserInfo(parsedClaims);
		}

		private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
			return (source) -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
		}
	}
}
