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
import jp.openstandia.connector.keycloak.KeycloakConfiguration;
import jp.openstandia.connector.keycloak.KeycloakGroupHandler;
import jp.openstandia.connector.keycloak.KeycloakUserHandler;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class PaginationIT extends AbstractIntegrationTest {

    private static final ObjectClass USER_OBJECT_CLASS = KeycloakUserHandler.USER_OBJECT_CLASS;
    private static final ObjectClass GROUP_OBJECT_CLASS = KeycloakGroupHandler.GROUP_OBJECT_CLASS;
    private static final ObjectClass CLIENT_OBJECT_CLASS = KeycloakClientHandler.CLIENT_OBJECT_CLASS;
    private static final ObjectClass CLIENT_ROLE_OBJECT_CLASS = KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS;

    @Test
    void getUsersWithPagination() {
        // Use small page size to force multiple internal pages
        KeycloakConfiguration conf = newConfiguration();
        conf.setQueryPageSize(3);
        ConnectorFacade connector = newFacade(conf);

        // Create 7 users to span 3 pages (3 + 3 + 1)
        for (int i = 1; i <= 7; i++) {
            Set<Attribute> attrs = new HashSet<>();
            attrs.add(new Name("user" + i));
            attrs.add(AttributeBuilder.buildEnabled(true));
            connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
        }

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(USER_OBJECT_CLASS, null, handler, defaultSearchOperation());

        assertEquals(7, results.size());
    }

    @Test
    void getGroupsWithPagination() {
        // Use small page size to force multiple internal pages
        KeycloakConfiguration conf = newConfiguration();
        conf.setQueryPageSize(3);
        ConnectorFacade connector = newFacade(conf);

        // Create 7 groups to span 3 pages (3 + 3 + 1)
        for (int i = 1; i <= 7; i++) {
            Set<Attribute> attrs = new HashSet<>();
            attrs.add(new Name("group" + i));
            connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
        }

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(GROUP_OBJECT_CLASS, null, handler, defaultSearchOperation());

        assertEquals(7, results.size());
    }

    @Test
    void getClientsWithPagination() {
        KeycloakConfiguration conf = newConfiguration();
        conf.setQueryPageSize(3);
        ConnectorFacade connector = newFacade(conf);

        // Create 5 clients
        for (int i = 1; i <= 5; i++) {
            Set<Attribute> attrs = new HashSet<>();
            attrs.add(new Name("paging-client" + i));
            attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
            attrs.add(AttributeBuilder.buildEnabled(true));
            connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
        }

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(CLIENT_OBJECT_CLASS, null, handler, defaultSearchOperation());

        // Default clients + our 5
        Set<String> ourClients = new HashSet<>();
        for (ConnectorObject co : results) {
            String name = co.getName().getNameValue();
            if (name.startsWith("paging-client")) {
                ourClients.add(name);
            }
        }
        assertEquals(5, ourClients.size());
    }

    @Test
    void getClientRolesWithPagination() {
        KeycloakConfiguration conf = newConfiguration();
        conf.setQueryPageSize(3);
        ConnectorFacade connector = newFacade(conf);

        // Create a client
        Set<Attribute> clientAttrs = new HashSet<>();
        clientAttrs.add(new Name("paging-role-client"));
        clientAttrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        clientAttrs.add(AttributeBuilder.buildEnabled(true));
        Uid clientUid = connector.create(CLIENT_OBJECT_CLASS, clientAttrs, new OperationOptionsBuilder().build());

        // Create 5 roles on that client
        for (int i = 1; i <= 5; i++) {
            Set<Attribute> roleAttrs = new HashSet<>();
            roleAttrs.add(new Name(clientUid.getUidValue() + "/paging-role" + i));
            connector.create(CLIENT_ROLE_OBJECT_CLASS, roleAttrs, new OperationOptionsBuilder().build());
        }

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(CLIENT_ROLE_OBJECT_CLASS, null, handler, defaultSearchOperation());

        // Find our roles among all client roles
        Set<String> ourRoles = new HashSet<>();
        for (ConnectorObject co : results) {
            String name = co.getName().getNameValue();
            if (name.contains("paging-role")) {
                ourRoles.add(name);
            }
        }
        assertEquals(5, ourRoles.size());
    }

    @Test
    void getUsersHandlerStopsEarly() {
        // Verify that handler returning false stops iteration
        KeycloakConfiguration conf = newConfiguration();
        conf.setQueryPageSize(2);
        ConnectorFacade connector = newFacade(conf);

        for (int i = 1; i <= 5; i++) {
            Set<Attribute> attrs = new HashSet<>();
            attrs.add(new Name("user" + i));
            attrs.add(AttributeBuilder.buildEnabled(true));
            connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
        }

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            // Stop after 3 results
            return results.size() < 3;
        };
        connector.search(USER_OBJECT_CLASS, null, handler, defaultSearchOperation());

        assertEquals(3, results.size());
    }
}
