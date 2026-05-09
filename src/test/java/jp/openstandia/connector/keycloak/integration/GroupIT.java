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
import jp.openstandia.connector.keycloak.KeycloakGroupHandler;
import jp.openstandia.connector.keycloak.KeycloakRealmRoleHandler;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class GroupIT extends AbstractIntegrationTest {

    private static final ObjectClass GROUP_OBJECT_CLASS = KeycloakGroupHandler.GROUP_OBJECT_CLASS;

    // --- Create ---

    @Test
    void addGroup() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("group1"));

        Uid uid = connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        assertNotNull(uid);
        assertNotNull(uid.getUidValue());
        assertEquals("group1", uid.getNameHintValue());

        ConnectorObject result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("group1")),
                defaultGetOperation("path"));

        assertEquals("group1", result.getName().getNameValue());
        assertEquals("/group1", singleAttr(result, "path"));
    }

    @Test
    void addGroupButAlreadyExists() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("group1"));

        connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        assertThrows(AlreadyExistsException.class, () -> {
            connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
        });
    }

    // --- Update ---

    @Test
    void updateGroupName() {
        Uid uid = createTestGroup("old-name");

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build(Name.NAME, "new-name"));

        connector.updateDelta(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("old-name")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("new-name")), defaultGetOperation());

        assertEquals("new-name", result.getName().getNameValue());
    }

    @Test
    void updateGroupButNotFound() {
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build(Name.NAME, "new-name"));

        assertThrows(UnknownUidException.class, () -> {
            connector.updateDelta(GROUP_OBJECT_CLASS,
                    new Uid("nonexistent-id", new Name("nonexistent")), modifications, new OperationOptionsBuilder().build());
        });
    }

    // --- Read ---

    @Test
    void getGroupByUid() {
        Uid uid = createTestGroup("group1");

        ConnectorObject result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("group1")),
                defaultGetOperation("path"));

        assertEquals(GROUP_OBJECT_CLASS, result.getObjectClass());
        assertEquals(uid.getUidValue(), result.getUid().getUidValue());
        assertEquals("group1", result.getName().getNameValue());
        assertEquals("/group1", singleAttr(result, "path"));
    }

    @Test
    void getGroupByName() {
        Uid uid = createTestGroup("group1");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(GROUP_OBJECT_CLASS, FilterBuilder.equalTo(new Name("group1")), handler, defaultSearchOperation());

        assertEquals(1, results.size());
        assertEquals(uid.getUidValue(), results.get(0).getUid().getUidValue());
        assertEquals("group1", results.get(0).getName().getNameValue());
    }

    // --- Search ---

    @Test
    void getGroups() {
        createTestGroup("group1");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        SearchResult searchResult = connector.search(GROUP_OBJECT_CLASS, null, handler, defaultSearchOperation());

        assertEquals(1, results.size());
        assertEquals("group1", results.get(0).getName().getNameValue());

        // Verify SearchResultsHandler.handleResult() was called
        assertNotNull(searchResult);
        assertTrue(searchResult.isAllResultsReturned());
    }

    @Test
    void getGroupsZero() {
        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(GROUP_OBJECT_CLASS, null, handler, defaultSearchOperation());

        assertEquals(0, results.size());
    }

    @Test
    void getGroupsTwo() {
        createTestGroup("group1");
        createTestGroup("group2");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(GROUP_OBJECT_CLASS, null, handler, defaultSearchOperation());

        assertEquals(2, results.size());
    }

    // --- Delete ---

    @Test
    void deleteGroup() {
        Uid uid = createTestGroup("group1");

        connector.delete(GROUP_OBJECT_CLASS, new Uid(uid.getUidValue(), new Name("group1")), new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("group1")), defaultGetOperation());
        assertNull(result);
    }

    // --- Lifecycle ---

    @Test
    void groupLifecycle() {
        // Create
        Uid uid = createTestGroup("lifecycle-group");
        assertNotNull(uid);

        // Get
        ConnectorObject result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("lifecycle-group")),
                defaultGetOperation("path"));
        assertEquals("lifecycle-group", result.getName().getNameValue());
        assertEquals("/lifecycle-group", singleAttr(result, "path"));

        // Update
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build(Name.NAME, "renamed-group"));

        connector.updateDelta(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("lifecycle-group")), modifications, new OperationOptionsBuilder().build());

        result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("renamed-group")), defaultGetOperation());
        assertEquals("renamed-group", result.getName().getNameValue());

        // Delete
        connector.delete(GROUP_OBJECT_CLASS, new Uid(uid.getUidValue(), new Name("renamed-group")), new OperationOptionsBuilder().build());

        result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("renamed-group")), defaultGetOperation());
        assertNull(result);
    }

    // --- Realm Roles ---

    @Test
    void addGroupWithRealmRoles() {
        connector.create(KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS,
                set(new Name("grp-role1")), new OperationOptionsBuilder().build());
        connector.create(KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS,
                set(new Name("grp-role2")), new OperationOptionsBuilder().build());

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("role-group"));
        attrs.add(AttributeBuilder.build("realmRoles", list("grp-role1", "grp-role2")));

        Uid uid = connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("role-group")), defaultGetOperation("realmRoles"));

        List<Object> roles = multiAttr(result, "realmRoles");
        assertTrue(roles.contains("grp-role1"));
        assertTrue(roles.contains("grp-role2"));
    }

    @Test
    void updateGroupRealmRoles() {
        connector.create(KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS,
                set(new Name("grp-ra")), new OperationOptionsBuilder().build());
        connector.create(KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS,
                set(new Name("grp-rb")), new OperationOptionsBuilder().build());

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("role-group"));
        attrs.add(AttributeBuilder.build("realmRoles", list("grp-ra")));
        Uid uid = connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("realmRoles", list("grp-rb"), list("grp-ra")));

        connector.updateDelta(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("role-group")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("role-group")), defaultGetOperation("realmRoles"));

        List<Object> roles = multiAttr(result, "realmRoles");
        assertTrue(roles.contains("grp-rb"));
        assertFalse(roles.contains("grp-ra"));
    }

    // --- Client Roles ---

    @Test
    void addGroupWithClientRoles() {
        Set<Attribute> clientAttrs = new HashSet<>();
        clientAttrs.add(new Name("grp-role-client"));
        clientAttrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        clientAttrs.add(AttributeBuilder.buildEnabled(true));
        Uid clientUid = connector.create(KeycloakClientHandler.CLIENT_OBJECT_CLASS, clientAttrs, new OperationOptionsBuilder().build());
        String clientUUID = clientUid.getUidValue();

        Uid cr1 = connector.create(KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS,
                set(new Name(clientUUID + "/gcr1")), new OperationOptionsBuilder().build());
        Uid cr2 = connector.create(KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS,
                set(new Name(clientUUID + "/gcr2")), new OperationOptionsBuilder().build());

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("role-group"));
        attrs.add(AttributeBuilder.build("clientRoles", list(cr1.getUidValue(), cr2.getUidValue())));

        Uid uid = connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("role-group")), defaultGetOperation("clientRoles"));

        List<Object> clientRoles = multiAttr(result, "clientRoles");
        assertTrue(clientRoles.contains(cr1.getUidValue()));
        assertTrue(clientRoles.contains(cr2.getUidValue()));
    }

    @Test
    void updateGroupClientRoles() {
        Set<Attribute> clientAttrs = new HashSet<>();
        clientAttrs.add(new Name("grp-role-client"));
        clientAttrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        clientAttrs.add(AttributeBuilder.buildEnabled(true));
        Uid clientUid = connector.create(KeycloakClientHandler.CLIENT_OBJECT_CLASS, clientAttrs, new OperationOptionsBuilder().build());
        String clientUUID = clientUid.getUidValue();

        Uid crA = connector.create(KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS,
                set(new Name(clientUUID + "/gcr-a")), new OperationOptionsBuilder().build());
        Uid crB = connector.create(KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS,
                set(new Name(clientUUID + "/gcr-b")), new OperationOptionsBuilder().build());

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("role-group"));
        attrs.add(AttributeBuilder.build("clientRoles", list(crA.getUidValue())));
        Uid uid = connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("clientRoles",
                list(crB.getUidValue()), list(crA.getUidValue())));

        connector.updateDelta(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("role-group")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("role-group")), defaultGetOperation("clientRoles"));

        List<Object> clientRoles = multiAttr(result, "clientRoles");
        assertTrue(clientRoles.contains(crB.getUidValue()));
        assertFalse(clientRoles.contains(crA.getUidValue()));
    }

    // --- Bulk role unassign (threshold=3: <=3 uses individual get, >3 uses listAll) ---

    @ParameterizedTest(name = "unassign {0} realm roles from group")
    @ValueSource(ints = {3, 4})
    void unassignRealmRolesFromGroup(int count) {
        List<String> roleNames = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            String name = "gr-role" + i;
            connector.create(KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS,
                    set(new Name(name)), new OperationOptionsBuilder().build());
            roleNames.add(name);
        }

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("role-group"));
        attrs.add(AttributeBuilder.build("realmRoles", roleNames));
        Uid uid = connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("realmRoles", null, roleNames));
        connector.updateDelta(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("role-group")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("role-group")), defaultGetOperation("realmRoles"));
        List<Object> roles = multiAttr(result, "realmRoles");
        for (String name : roleNames) {
            assertFalse(roles.contains(name), "Role " + name + " should be unassigned");
        }
    }

    @ParameterizedTest(name = "unassign {0} client roles from group")
    @ValueSource(ints = {3, 4})
    void unassignClientRolesFromGroup(int count) {
        Set<Attribute> clientAttrs = new HashSet<>();
        clientAttrs.add(new Name("unassign-client"));
        clientAttrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        clientAttrs.add(AttributeBuilder.buildEnabled(true));
        Uid clientUid = connector.create(KeycloakClientHandler.CLIENT_OBJECT_CLASS, clientAttrs, new OperationOptionsBuilder().build());

        List<String> roleUids = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            Uid crUid = connector.create(KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS,
                    set(new Name(clientUid.getUidValue() + "/gcr" + i)), new OperationOptionsBuilder().build());
            roleUids.add(crUid.getUidValue());
        }

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("role-group"));
        attrs.add(AttributeBuilder.build("clientRoles", roleUids));
        Uid uid = connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("clientRoles", null, roleUids));
        connector.updateDelta(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("role-group")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(GROUP_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("role-group")), defaultGetOperation("clientRoles"));
        List<Object> clientRoles = multiAttr(result, "clientRoles");
        for (String roleUid : roleUids) {
            assertFalse(clientRoles.contains(roleUid), "Client role " + roleUid + " should be unassigned");
        }
    }

    // --- Helpers ---

    private Uid createTestGroup(String name) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        return connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
    }
}
