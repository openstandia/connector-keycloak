/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package jp.openstandia.connector.keycloak.rest;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.ext.ContextResolver;
import jakarta.ws.rs.ext.Provider;

/**
 * A named {@code ContextResolver<ObjectMapper>} implementation that supplies a pre-configured
 * ObjectMapper to the RESTEasy Jackson provider.
 *
 * Using a named class (rather than a lambda or anonymous class) is required because
 * RESTEasy resolves the generic type {@code T} of {@code ContextResolver<T>} via reflection on
 * {@code Class.getGenericInterfaces()}. Lambda proxies do not carry reifiable generic type
 * information, causing:
 *   RESTEASY003920: Unable to instantiate ContextResolver
 *   -> NullPointerException: Cannot invoke "Class.getInterfaces()" because "root" is null
 *
 * By providing a concrete class, RESTEasy can correctly determine that this resolver
 * handles ObjectMapper and will call getContext(ObjectMapper.class) when
 * JacksonJsonProvider.locateMapper() fires.
 *
 * The ObjectMapper is configured WITHOUT calling findAndRegisterModules() / findModules(),
 * which would trigger Java ServiceLoader and discover modules from MidPoint's parent
 * classloader (e.g. ParameterNamesModule bound to a different Jackson version), causing:
 *   ServiceConfigurationError: ParameterNamesModule not a subtype
 *
 * Modules are registered explicitly from the connector's own bundled jars only.
 */
@Provider
@Produces(MediaType.APPLICATION_JSON)
public class KeycloakObjectMapperContextResolver implements ContextResolver<ObjectMapper> {

    private static final ObjectMapper MAPPER;

    static {
        MAPPER = new ObjectMapper();
        MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        MAPPER.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        // Register only modules bundled with this connector — do NOT call
        // findAndRegisterModules() since that invokes ServiceLoader and risks
        // picking up incompatible modules from MidPoint's classloader.
        MAPPER.registerModule(new JavaTimeModule());
        MAPPER.registerModule(new Jdk8Module());
    }

    @Override
    public ObjectMapper getContext(Class<?> type) {
        return MAPPER;
    }
}
