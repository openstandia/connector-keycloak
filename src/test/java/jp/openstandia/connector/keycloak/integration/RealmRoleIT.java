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
package jp.openstandia.connector.keycloak.integration;

import jp.openstandia.connector.keycloak.KeycloakRealmRoleHandler;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class RealmRoleIT extends AbstractIntegrationTest {

    private static final ObjectClass REALM_ROLE_OBJECT_CLASS = KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS;

    // --- Create ---

    @Test
    void addRealmRole() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("test-role"));
        attrs.add(AttributeBuilder.build("description", "A test role"));

        Uid uid = connector.create(REALM_ROLE_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        assertNotNull(uid);
        assertNotNull(uid.getUidValue());

        ConnectorObject result = connector.getObject(REALM_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-role")),
                defaultGetOperation("description"));

        assertEquals("test-role", result.getName().getNameValue());
        assertEquals("A test role", singleAttr(result, "description"));
    }

    // --- Update ---

    @Test
    void updateRealmRole() {
        Uid uid = createTestRole("update-role");

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("description", "Updated description"));

        connector.updateDelta(REALM_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("update-role")),
                modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(REALM_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("update-role")),
                defaultGetOperation("description"));

        assertEquals("Updated description", singleAttr(result, "description"));
    }

    @Test
    void updateRealmRoleButNotFound() {
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("description", "desc"));

        assertThrows(UnknownUidException.class, () -> {
            connector.updateDelta(REALM_ROLE_OBJECT_CLASS,
                    new Uid("nonexistent-id", new Name("nonexistent")),
                    modifications, new OperationOptionsBuilder().build());
        });
    }

    // --- Read ---

    @Test
    void getRealmRoleByUid() {
        Uid uid = createTestRole("read-role");

        ConnectorObject result = connector.getObject(REALM_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("read-role")),
                defaultGetOperation("description"));

        assertEquals(REALM_ROLE_OBJECT_CLASS, result.getObjectClass());
        assertEquals(uid.getUidValue(), result.getUid().getUidValue());
        assertEquals("read-role", result.getName().getNameValue());
    }

    @Test
    void getRealmRoleByName() {
        Uid uid = createTestRole("search-role");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(REALM_ROLE_OBJECT_CLASS,
                FilterBuilder.equalTo(new Name("search-role")),
                handler, defaultSearchOperation());

        assertEquals(1, results.size());
        assertEquals(uid.getUidValue(), results.get(0).getUid().getUidValue());
    }

    // --- Search ---

    @Test
    void getRealmRoles() {
        createTestRole("role1");
        createTestRole("role2");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        SearchResult searchResult = connector.search(REALM_ROLE_OBJECT_CLASS, null, handler, defaultSearchOperation());

        // Default roles exist, so at least our 2
        Set<String> ourRoles = new HashSet<>();
        for (ConnectorObject co : results) {
            String name = co.getName().getNameValue();
            if (name.startsWith("role")) {
                ourRoles.add(name);
            }
        }
        assertEquals(set("role1", "role2"), ourRoles);

        // Verify SearchResultsHandler.handleResult() was called
        assertNotNull(searchResult);
        assertTrue(searchResult.isAllResultsReturned());
    }

    // --- Delete ---

    @Test
    void deleteRealmRole() {
        Uid uid = createTestRole("delete-role");

        connector.delete(REALM_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("delete-role")),
                new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(REALM_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("delete-role")),
                defaultGetOperation());
        assertNull(result);
    }

    // --- Helpers ---

    private Uid createTestRole(String name) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        return connector.create(REALM_ROLE_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
    }
}
