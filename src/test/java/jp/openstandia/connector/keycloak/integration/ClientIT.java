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
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class ClientIT extends AbstractIntegrationTest {

    private static final ObjectClass CLIENT_OBJECT_CLASS = KeycloakClientHandler.CLIENT_OBJECT_CLASS;

    // --- Create ---

    @Test
    void addClient() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("test-client"));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.buildEnabled(true));

        Uid uid = connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        assertNotNull(uid);
        assertNotNull(uid.getUidValue());
        assertEquals("test-client", uid.getNameHintValue());

        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")),
                defaultGetOperation("protocol", "publicClient"));

        assertEquals("test-client", result.getName().getNameValue());
        assertEquals("openid-connect", singleAttr(result, "protocol"));
    }

    // --- Read ---

    @Test
    void getClientByUid() {
        Uid uid = createTestClient("test-client");

        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")),
                defaultGetOperation("protocol"));

        assertEquals(CLIENT_OBJECT_CLASS, result.getObjectClass());
        assertEquals(uid.getUidValue(), result.getUid().getUidValue());
        assertEquals("test-client", result.getName().getNameValue());
        assertEquals("openid-connect", singleAttr(result, "protocol"));
    }

    /**
     * This test verifies the bug fix where getClient by name was comparing
     * rep.getName() instead of rep.getClientId(). The clientId ("test-client")
     * and the display name ("Test Client Display") are different, so the old
     * buggy code would fail to find the client.
     */
    @Test
    void getClientByName() {
        // Create client with clientId different from display name
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("test-client"));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.build("name", "Test Client Display"));
        attrs.add(AttributeBuilder.buildEnabled(true));

        Uid uid = connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Search by clientId (Name) — this would fail with the old getName() bug
        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(CLIENT_OBJECT_CLASS, FilterBuilder.equalTo(new Name("test-client")), handler, defaultSearchOperation());

        assertEquals(1, results.size());
        assertEquals(uid.getUidValue(), results.get(0).getUid().getUidValue());
        assertEquals("test-client", results.get(0).getName().getNameValue());
    }

    // --- Search ---

    @Test
    void getClients() {
        createTestClient("client1");
        createTestClient("client2");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        SearchResult searchResult = connector.search(CLIENT_OBJECT_CLASS, null, handler, defaultSearchOperation());

        // Keycloak has default clients (account, admin-cli, etc.) + our 2
        assertTrue(results.size() >= 2);

        Set<String> clientIds = new HashSet<>();
        for (ConnectorObject co : results) {
            clientIds.add(co.getName().getNameValue());
        }
        assertTrue(clientIds.contains("client1"));
        assertTrue(clientIds.contains("client2"));

        // Verify SearchResultsHandler.handleResult() was called
        assertNotNull(searchResult);
        assertTrue(searchResult.isAllResultsReturned());
    }

    // --- Secret as GuardedString ---

    @Test
    void getClientSecretAsGuardedString() {
        // Create a confidential client (non-public) so it has a secret
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("confidential-client"));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.build("publicClient", false));
        attrs.add(AttributeBuilder.buildEnabled(true));

        Uid uid = connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("confidential-client")),
                defaultGetOperation("secret"));

        Attribute secretAttr = result.getAttributeByName("secret");
        assertNotNull(secretAttr);
        Object secretValue = secretAttr.getValue().get(0);
        assertInstanceOf(GuardedString.class, secretValue);

        // Verify the secret is non-empty
        String plain = toPlain((GuardedString) secretValue);
        assertNotNull(plain);
        assertFalse(plain.isEmpty());
    }

    // --- Delete ---

    @Test
    void deleteClient() {
        Uid uid = createTestClient("test-client");

        connector.delete(CLIENT_OBJECT_CLASS, new Uid(uid.getUidValue(), new Name("test-client")), new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")), defaultGetOperation());
        assertNull(result);
    }

    // --- Helpers ---

    private Uid createTestClient(String clientId) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(clientId));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        return connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
    }
}
