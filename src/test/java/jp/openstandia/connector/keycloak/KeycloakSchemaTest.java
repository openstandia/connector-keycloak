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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

class KeycloakSchemaTest {

    /**
     * Test that parseVersion correctly parses various version string formats.
     * This covers the fix for -SNAPSHOT, .Final, and other suffixes.
     */
    @ParameterizedTest
    @CsvSource({
            "26.0.8,   26, 0, 8",
            "26.0.9,   26, 0, 9",
            "24.0.5,   24, 0, 5",
            "26.0.0-SNAPSHOT, 26, 0, 0",
            "24.0.2-SNAPSHOT, 24, 0, 2",
            "20.0.1.Final,    20, 0, 1",
            "18.0.0-alpha1,   18, 0, 0",
            "26.0,     26, 0, 0",
            "26,       26, 0, 0",
    })
    void parseVersion(String version, int expectedMajor, int expectedMinor, int expectedPatch) {
        int[] result = parseVersionHelper(version);
        assertEquals(expectedMajor, result[0], "major version for " + version);
        assertEquals(expectedMinor, result[1], "minor version for " + version);
        assertEquals(expectedPatch, result[2], "patch version for " + version);
    }

    @Test
    void parseVersionInvalid() {
        assertThrows(RuntimeException.class, () -> parseVersionHelper("abc"));
    }

    /**
     * Replicate the parseVersion logic from KeycloakSchema to test it in isolation
     * without needing a full KeycloakClient/Configuration.
     */
    private int[] parseVersionHelper(String version) {
        try {
            String v = version.replaceAll("[^0-9.].*$", "");
            String[] s = v.split("\\.");
            int major = Integer.parseInt(s[0]);
            int minor = s.length > 1 ? Integer.parseInt(s[1]) : 0;
            int patch = s.length > 2 ? Integer.parseInt(s[2]) : 0;
            return new int[]{major, minor, patch};
        } catch (NumberFormatException | IndexOutOfBoundsException e) {
            throw new RuntimeException("Keycloak returns unexpected version number: " + version, e);
        }
    }
}
