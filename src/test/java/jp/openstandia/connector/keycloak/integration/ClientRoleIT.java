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

import jp.openstandia.connector.keycloak.KeycloakClientHandler;
import jp.openstandia.connector.keycloak.KeycloakClientRoleHandler;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class ClientRoleIT extends AbstractIntegrationTest {

    private static final ObjectClass CLIENT_OBJECT_CLASS = KeycloakClientHandler.CLIENT_OBJECT_CLASS;
    private static final ObjectClass CLIENT_ROLE_OBJECT_CLASS = KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS;

    private String clientUUID;

    @Override
    @BeforeEach
    void setUp() {
        super.setUp();
        // Create a client to hold roles
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("role-test-client"));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        Uid uid = connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
        clientUUID = uid.getUidValue();
    }

    // --- Create ---

    @Test
    void addClientRole() {
        String roleName = clientUUID + "/test-role";

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(roleName));
        attrs.add(AttributeBuilder.build("description", "A test role"));

        Uid uid = connector.create(CLIENT_ROLE_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        assertNotNull(uid);
        assertNotNull(uid.getUidValue());

        ConnectorObject result = connector.getObject(CLIENT_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name(roleName)),
                defaultGetOperation("description"));

        assertEquals(roleName, result.getName().getNameValue());
        assertEquals("A test role", singleAttr(result, "description"));
    }

    // --- Update ---

    @Test
    void updateClientRole() {
        Uid uid = createTestRole("update-role");

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("description", "Updated description"));

        connector.updateDelta(CLIENT_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name(clientUUID + "/update-role")),
                modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(CLIENT_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name(clientUUID + "/update-role")),
                defaultGetOperation("description"));

        assertEquals("Updated description", singleAttr(result, "description"));
    }

    @Test
    void updateClientRoleButNotFound() {
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("description", "desc"));

        assertThrows(UnknownUidException.class, () -> {
            connector.updateDelta(CLIENT_ROLE_OBJECT_CLASS,
                    new Uid(clientUUID + "/nonexistent", new Name(clientUUID + "/nonexistent")),
                    modifications, new OperationOptionsBuilder().build());
        });
    }

    // --- Read ---

    @Test
    void getClientRoleByUid() {
        Uid uid = createTestRole("read-role");

        ConnectorObject result = connector.getObject(CLIENT_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name(clientUUID + "/read-role")),
                defaultGetOperation("description"));

        assertEquals(CLIENT_ROLE_OBJECT_CLASS, result.getObjectClass());
        assertEquals(uid.getUidValue(), result.getUid().getUidValue());
        assertEquals(clientUUID + "/read-role", result.getName().getNameValue());
    }

    @Test
    void getClientRoleByName() {
        Uid uid = createTestRole("search-role");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(CLIENT_ROLE_OBJECT_CLASS,
                FilterBuilder.equalTo(new Name(clientUUID + "/search-role")),
                handler, defaultSearchOperation());

        assertEquals(1, results.size());
        assertEquals(uid.getUidValue(), results.get(0).getUid().getUidValue());
    }

    // --- Search ---

    @Test
    void getClientRoles() {
        createTestRole("role1");
        createTestRole("role2");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        SearchResult searchResult = connector.search(CLIENT_ROLE_OBJECT_CLASS, null, handler, defaultSearchOperation());

        // Default roles exist per client, so at least our 2
        assertTrue(results.size() >= 2);

        // Verify SearchResultsHandler.handleResult() was called
        assertNotNull(searchResult);
        assertTrue(searchResult.isAllResultsReturned());
    }

    // --- Delete ---

    @Test
    void deleteClientRole() {
        String roleName = clientUUID + "/delete-role";
        Uid uid = createTestRole("delete-role");

        connector.delete(CLIENT_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name(roleName)),
                new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(CLIENT_ROLE_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name(roleName)),
                defaultGetOperation());
        assertNull(result);
    }

    // --- Helpers ---

    private Uid createTestRole(String roleName) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(clientUUID + "/" + roleName));
        return connector.create(CLIENT_ROLE_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
    }
}
