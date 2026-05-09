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
package jp.openstandia.connector.keycloak;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class KeycloakConfigurationTest {

    // --- getNormalizedServerUrl ---

    @ParameterizedTest
    @CsvSource({
            "https://iam.example.com,       https://iam.example.com",
            "https://iam.example.com/,      https://iam.example.com",
            "https://iam.example.com///,    https://iam.example.com",
            "https://iam.example.com/iam,   https://iam.example.com/iam",
            "https://iam.example.com/iam/,  https://iam.example.com/iam",
            "http://localhost:8080,          http://localhost:8080",
            "http://localhost:8080/,         http://localhost:8080",
    })
    void getNormalizedServerUrl(String input, String expected) {
        KeycloakConfiguration conf = new KeycloakConfiguration();
        conf.setServerUrl(input);
        assertEquals(expected, conf.getNormalizedServerUrl());
    }

    @Test
    void getNormalizedServerUrlNull() {
        KeycloakConfiguration conf = new KeycloakConfiguration();
        assertNull(conf.getNormalizedServerUrl());
    }

    // --- validate ---

    @Test
    void validateSuccess() {
        KeycloakConfiguration conf = newValidConfiguration();
        assertDoesNotThrow(conf::validate);
    }

    @Test
    void validateBlankServerUrl() {
        KeycloakConfiguration conf = newValidConfiguration();
        conf.setServerUrl("");
        assertThrows(ConfigurationException.class, conf::validate);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ftp://example.com", "not-a-url"})
    void validateInvalidServerUrl(String url) {
        KeycloakConfiguration conf = newValidConfiguration();
        conf.setServerUrl(url);
        assertThrows(ConfigurationException.class, conf::validate);
    }

    @Test
    void validateMissingCredentials() {
        KeycloakConfiguration conf = new KeycloakConfiguration();
        conf.setServerUrl("https://example.com");
        // No username/password or clientSecret
        assertThrows(ConfigurationException.class, conf::validate);
    }

    // --- Helpers ---

    private KeycloakConfiguration newValidConfiguration() {
        KeycloakConfiguration conf = new KeycloakConfiguration();
        conf.setServerUrl("https://iam.example.com");
        conf.setUsername("admin");
        conf.setPassword(new GuardedString("password".toCharArray()));
        conf.setClientId("admin-cli");
        return conf;
    }
}
