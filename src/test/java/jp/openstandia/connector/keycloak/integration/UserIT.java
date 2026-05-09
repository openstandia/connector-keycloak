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
import jp.openstandia.connector.keycloak.KeycloakRealmRoleHandler;
import jp.openstandia.connector.keycloak.KeycloakUserHandler;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class UserIT extends AbstractIntegrationTest {

    private static final ObjectClass USER_OBJECT_CLASS = KeycloakUserHandler.USER_OBJECT_CLASS;

    // --- Create ---

    @Test
    void addUser() {
        String userName = "foo";
        String email = "foo@example.com";
        String firstName = "Foo";
        String lastName = "Bar";

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(userName));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.buildPassword("secret".toCharArray()));
        attrs.add(AttributeBuilder.build("email", email));
        attrs.add(AttributeBuilder.build("emailVerified", true));
        attrs.add(AttributeBuilder.build("firstName", firstName));
        attrs.add(AttributeBuilder.build("lastName", lastName));

        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        assertNotNull(uid);
        assertNotNull(uid.getUidValue());
        assertEquals(userName, uid.getNameHintValue());

        // Verify by fetching the user
        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name(userName)), defaultGetOperation("groups"));

        assertEquals(userName, result.getName().getNameValue());
        assertEquals(email, singleAttr(result, "email"));
        assertEquals(true, singleAttr(result, "emailVerified"));
        assertEquals(firstName, singleAttr(result, "firstName"));
        assertEquals(lastName, singleAttr(result, "lastName"));
        assertEquals(true, singleAttr(result, OperationalAttributes.ENABLE_NAME));
        assertNotNull(singleAttr(result, "createdTimestamp"));
    }

    @Test
    void addUserWithGroups() {
        // Create groups first
        Uid g1 = createTestGroup("group1");
        Uid g2 = createTestGroup("group2");

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("groups", list(g1.getUidValue(), g2.getUidValue())));

        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        assertNotNull(uid);

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation("groups"));

        List<Object> groups = multiAttr(result, "groups");
        assertEquals(set(g1.getUidValue(), g2.getUidValue()), new HashSet<>(groups));
    }

    @Test
    void addUserWithInactive() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(false));

        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        assertNotNull(uid);

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation());

        assertEquals(false, singleAttr(result, OperationalAttributes.ENABLE_NAME));
    }

    @Test
    void addUserButAlreadyExists() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.buildPassword("secret".toCharArray()));

        connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        assertThrows(AlreadyExistsException.class, () -> {
            connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
        });
    }

    // --- Update ---

    @Test
    void updateUser() {
        Uid uid = createTestUser("hoge", "hoge@example.com", "First", "Last");

        String newFirstName = "Foo";
        String newLastName = "Bar";
        String newUserName = "foo";

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build(Name.NAME, newUserName));
        modifications.add(AttributeDeltaBuilder.build("firstName", newFirstName));
        modifications.add(AttributeDeltaBuilder.build("lastName", newLastName));
        modifications.add(AttributeDeltaBuilder.buildEnabled(true));

        Set<AttributeDelta> affected = connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("hoge")), modifications, new OperationOptionsBuilder().build());

        assertNull(affected);

        // Verify by fetching with new name
        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name(newUserName)), defaultGetOperation());

        assertEquals(newUserName, result.getName().getNameValue());
        assertEquals(newFirstName, singleAttr(result, "firstName"));
        assertEquals(newLastName, singleAttr(result, "lastName"));
        assertEquals(true, singleAttr(result, OperationalAttributes.ENABLE_NAME));
    }

    @Test
    void updateUserGroups() {
        Uid g1 = createTestGroup("group1");
        Uid g2 = createTestGroup("group2");
        Uid g3 = createTestGroup("group3");

        // Create user with group2, group3
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("groups", list(g2.getUidValue(), g3.getUidValue())));
        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Add group1, remove group3
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("groups",
                list(g1.getUidValue()), list(g3.getUidValue())));

        connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation("groups"));

        List<Object> groups = multiAttr(result, "groups");
        assertEquals(set(g1.getUidValue(), g2.getUidValue()), new HashSet<>(groups));
    }

    @Test
    void updateUserButNotFound() {
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("firstName", "Foo"));

        assertThrows(UnknownUidException.class, () -> {
            connector.updateDelta(USER_OBJECT_CLASS,
                    new Uid("nonexistent-id", new Name("nonexistent")), modifications, new OperationOptionsBuilder().build());
        });
    }

    // --- Read ---

    @Test
    void getUserByUid() {
        Uid uid = createTestUser("foo", "foo@example.com", "Foo", "Bar");

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation());

        assertEquals(USER_OBJECT_CLASS, result.getObjectClass());
        assertEquals(uid.getUidValue(), result.getUid().getUidValue());
        assertEquals("foo", result.getName().getNameValue());
        assertEquals("foo@example.com", singleAttr(result, "email"));
        assertEquals("Foo", singleAttr(result, "firstName"));
        assertEquals("Bar", singleAttr(result, "lastName"));
        assertEquals(true, singleAttr(result, OperationalAttributes.ENABLE_NAME));
        assertNotNull(singleAttr(result, "createdTimestamp"));
        // groups not requested, should not be present
        assertNull(result.getAttributeByName("groups"));
    }

    @Test
    void getUserByName() {
        Uid uid = createTestUser("foo", "foo@example.com", "Foo", "Bar");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(USER_OBJECT_CLASS, FilterBuilder.equalTo(new Name("foo")), handler, defaultSearchOperation());

        assertEquals(1, results.size());
        ConnectorObject result = results.get(0);
        assertEquals(uid.getUidValue(), result.getUid().getUidValue());
        assertEquals("foo", result.getName().getNameValue());
        assertEquals("foo@example.com", singleAttr(result, "email"));
    }

    // --- Search ---

    @Test
    void getUsers() {
        createTestUser("foo", "foo@example.com", "Foo", "Bar");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        SearchResult searchResult = connector.search(USER_OBJECT_CLASS, null, handler, defaultSearchOperation());

        assertEquals(1, results.size());
        assertEquals("foo", results.get(0).getName().getNameValue());

        // Verify SearchResultsHandler.handleResult() was called
        assertNotNull(searchResult);
        assertTrue(searchResult.isAllResultsReturned());
    }

    @Test
    void getUsersZero() {
        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(USER_OBJECT_CLASS, null, handler, defaultSearchOperation());

        assertEquals(0, results.size());
    }

    @Test
    void getUsersTwo() {
        createTestUser("user1", "user1@example.com", "User", "One");
        createTestUser("user2", "user2@example.com", "User", "Two");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(USER_OBJECT_CLASS, null, handler, defaultSearchOperation());

        assertEquals(2, results.size());
    }

    // --- Delete ---

    @Test
    void deleteUser() {
        Uid uid = createTestUser("foo", "foo@example.com", "Foo", "Bar");

        connector.delete(USER_OBJECT_CLASS, new Uid(uid.getUidValue(), new Name("foo")), new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation());
        assertNull(result);
    }

    // --- Lifecycle ---

    @Test
    void userLifecycle() {
        // Create
        Uid uid = createTestUser("lifecycle-user", "lc@example.com", "Life", "Cycle");

        assertNotNull(uid);
        assertNotNull(uid.getUidValue());

        // Get by UID
        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("lifecycle-user")), defaultGetOperation());
        assertEquals("lifecycle-user", result.getName().getNameValue());
        assertEquals("lc@example.com", singleAttr(result, "email"));

        // Update
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("firstName", "Updated"));
        modifications.add(AttributeDeltaBuilder.buildEnabled(false));

        connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("lifecycle-user")), modifications, new OperationOptionsBuilder().build());

        result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("lifecycle-user")), defaultGetOperation());
        assertEquals("Updated", singleAttr(result, "firstName"));
        assertEquals(false, singleAttr(result, OperationalAttributes.ENABLE_NAME));

        // Delete
        connector.delete(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("lifecycle-user")), new OperationOptionsBuilder().build());

        result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("lifecycle-user")), defaultGetOperation());
        assertNull(result);
    }

    // --- Required Actions ---

    @Test
    void addUserWithRequiredActions() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("requiredActions", list("UPDATE_PASSWORD", "VERIFY_EMAIL")));

        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation());

        List<Object> actions = multiAttr(result, "requiredActions");
        assertTrue(actions.contains("UPDATE_PASSWORD"));
        assertTrue(actions.contains("VERIFY_EMAIL"));
    }

    @Test
    void updateUserRequiredActionsAddOnly() {
        // Create user with one action
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("requiredActions", list("UPDATE_PASSWORD")));
        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Add VERIFY_EMAIL without removing UPDATE_PASSWORD
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("requiredActions", list("VERIFY_EMAIL"), null));

        connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation());

        List<Object> actions = multiAttr(result, "requiredActions");
        assertTrue(actions.contains("UPDATE_PASSWORD"), "Existing action should be preserved");
        assertTrue(actions.contains("VERIFY_EMAIL"), "New action should be added");
    }

    @Test
    void updateUserRequiredActionsRemove() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("requiredActions", list("UPDATE_PASSWORD", "VERIFY_EMAIL")));
        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Remove UPDATE_PASSWORD, keep VERIFY_EMAIL
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("requiredActions", null, list("UPDATE_PASSWORD")));

        connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation());

        List<Object> actions = multiAttr(result, "requiredActions");
        assertFalse(actions.contains("UPDATE_PASSWORD"), "Removed action should be gone");
        assertTrue(actions.contains("VERIFY_EMAIL"), "Remaining action should be preserved");
    }

    @Test
    void updateUserRequiredActionsAddAndRemove() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("requiredActions", list("UPDATE_PASSWORD", "VERIFY_EMAIL")));
        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Add CONFIGURE_TOTP, remove UPDATE_PASSWORD simultaneously
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("requiredActions",
                list("CONFIGURE_TOTP"), list("UPDATE_PASSWORD")));

        connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation());

        List<Object> actions = multiAttr(result, "requiredActions");
        assertFalse(actions.contains("UPDATE_PASSWORD"));
        assertTrue(actions.contains("VERIFY_EMAIL"));
        assertTrue(actions.contains("CONFIGURE_TOTP"));
    }

    @Test
    void updateUserRequiredActionsRemoveNonExistent() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("requiredActions", list("VERIFY_EMAIL")));
        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Remove a non-existent action — should not throw
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("requiredActions",
                null, list("NON_EXISTENT_ACTION")));

        assertDoesNotThrow(() -> connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), modifications, new OperationOptionsBuilder().build()));

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation());

        List<Object> actions = multiAttr(result, "requiredActions");
        assertTrue(actions.contains("VERIFY_EMAIL"), "Existing action should be preserved");
    }

    @Test
    void updateUserRequiredActionsAddDuplicate() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("requiredActions", list("VERIFY_EMAIL")));
        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Add an action that already exists — should not duplicate
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("requiredActions",
                list("VERIFY_EMAIL"), null));

        assertDoesNotThrow(() -> connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), modifications, new OperationOptionsBuilder().build()));

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation());

        List<Object> actions = multiAttr(result, "requiredActions");
        assertEquals(1, actions.stream().filter(a -> a.equals("VERIFY_EMAIL")).count(),
                "Should not have duplicate actions");
    }

    // --- Realm Roles ---

    @Test
    void addUserWithRealmRoles() {
        // Create realm roles
        connector.create(KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS,
                set(new Name("test-role1")), new OperationOptionsBuilder().build());
        connector.create(KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS,
                set(new Name("test-role2")), new OperationOptionsBuilder().build());

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("realmRoles", list("test-role1", "test-role2")));

        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation("realmRoles"));

        List<Object> roles = multiAttr(result, "realmRoles");
        assertTrue(roles.contains("test-role1"));
        assertTrue(roles.contains("test-role2"));
    }

    @Test
    void updateUserRealmRoles() {
        connector.create(KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS,
                set(new Name("role-a")), new OperationOptionsBuilder().build());
        connector.create(KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS,
                set(new Name("role-b")), new OperationOptionsBuilder().build());

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("realmRoles", list("role-a")));
        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Add role-b, remove role-a
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("realmRoles", list("role-b"), list("role-a")));

        connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation("realmRoles"));

        List<Object> roles = multiAttr(result, "realmRoles");
        assertTrue(roles.contains("role-b"));
        assertFalse(roles.contains("role-a"));
    }

    // --- Client Roles ---

    @Test
    void addUserWithClientRoles() {
        // Create a client
        Set<Attribute> clientAttrs = new HashSet<>();
        clientAttrs.add(new Name("role-test-client"));
        clientAttrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        clientAttrs.add(AttributeBuilder.buildEnabled(true));
        Uid clientUid = connector.create(KeycloakClientHandler.CLIENT_OBJECT_CLASS, clientAttrs, new OperationOptionsBuilder().build());
        String clientUUID = clientUid.getUidValue();

        // Create client roles — Uid is now in "clientUUID/roleId" format
        Uid cr1Uid = connector.create(KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS,
                set(new Name(clientUUID + "/cr1")), new OperationOptionsBuilder().build());
        Uid cr2Uid = connector.create(KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS,
                set(new Name(clientUUID + "/cr2")), new OperationOptionsBuilder().build());

        // Create user with client roles using Uid values (clientUUID/roleId)
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("clientRoles", list(cr1Uid.getUidValue(), cr2Uid.getUidValue())));

        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation("clientRoles"));

        List<Object> clientRoles = multiAttr(result, "clientRoles");
        assertTrue(clientRoles.contains(cr1Uid.getUidValue()));
        assertTrue(clientRoles.contains(cr2Uid.getUidValue()));
    }

    @Test
    void updateUserClientRoles() {
        // Create a client
        Set<Attribute> clientAttrs = new HashSet<>();
        clientAttrs.add(new Name("role-test-client"));
        clientAttrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        clientAttrs.add(AttributeBuilder.buildEnabled(true));
        Uid clientUid = connector.create(KeycloakClientHandler.CLIENT_OBJECT_CLASS, clientAttrs, new OperationOptionsBuilder().build());
        String clientUUID = clientUid.getUidValue();

        Uid crAUid = connector.create(KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS,
                set(new Name(clientUUID + "/cr-a")), new OperationOptionsBuilder().build());
        Uid crBUid = connector.create(KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS,
                set(new Name(clientUUID + "/cr-b")), new OperationOptionsBuilder().build());

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("clientRoles", list(crAUid.getUidValue())));
        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Add cr-b, remove cr-a
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("clientRoles",
                list(crBUid.getUidValue()), list(crAUid.getUidValue())));

        connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation("clientRoles"));

        List<Object> clientRoles = multiAttr(result, "clientRoles");
        assertTrue(clientRoles.contains(crBUid.getUidValue()));
        assertFalse(clientRoles.contains(crAUid.getUidValue()));
    }

    // --- Bulk role unassign (threshold=3: <=3 uses individual get, >3 uses listAll) ---

    @ParameterizedTest(name = "unassign {0} realm roles from user")
    @ValueSource(ints = {3, 4})
    void unassignRealmRolesFromUser(int count) {
        List<String> roleNames = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            String name = "ur-role" + i;
            connector.create(KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS,
                    set(new Name(name)), new OperationOptionsBuilder().build());
            roleNames.add(name);
        }

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("realmRoles", roleNames));
        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("realmRoles", null, roleNames));
        connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation("realmRoles"));
        List<Object> roles = multiAttr(result, "realmRoles");
        for (String name : roleNames) {
            assertFalse(roles.contains(name), "Role " + name + " should be unassigned");
        }
    }

    @ParameterizedTest(name = "unassign {0} client roles from user")
    @ValueSource(ints = {3, 4})
    void unassignClientRolesFromUser(int count) {
        Set<Attribute> clientAttrs = new HashSet<>();
        clientAttrs.add(new Name("unassign-client"));
        clientAttrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        clientAttrs.add(AttributeBuilder.buildEnabled(true));
        Uid clientUid = connector.create(KeycloakClientHandler.CLIENT_OBJECT_CLASS, clientAttrs, new OperationOptionsBuilder().build());

        List<String> roleUids = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            Uid crUid = connector.create(KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS,
                    set(new Name(clientUid.getUidValue() + "/ucr" + i)), new OperationOptionsBuilder().build());
            roleUids.add(crUid.getUidValue());
        }

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("clientRoles", roleUids));
        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("clientRoles", null, roleUids));
        connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation("clientRoles"));
        List<Object> clientRoles = multiAttr(result, "clientRoles");
        for (String roleUid : roleUids) {
            assertFalse(clientRoles.contains(roleUid), "Client role " + roleUid + " should be unassigned");
        }
    }

    // --- Custom Attributes ---

    @Test
    void addUserWithCustomAttributes() {
        KeycloakConfiguration conf = newConfiguration();
        conf.setUserAttributes("custom1,custom2:multivalued");
        ConnectorFacade connector = newFacade(conf);

        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("custom1", "abc"));
        attrs.add(AttributeBuilder.build("custom2", list("123", "456")));

        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        assertNotNull(uid);

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation("custom1", "custom2"));

        assertEquals("abc", singleAttr(result, "custom1"));
        assertEquals(list("123", "456"), multiAttr(result, "custom2"));
    }

    @Test
    void updateUserCustomAttributes() {
        KeycloakConfiguration conf = newConfiguration();
        conf.setUserAttributes("custom1,custom2:multivalued");
        ConnectorFacade connector = newFacade(conf);

        // Create user with initial custom attributes
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("foo"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.build("custom1", "xyz"));
        attrs.add(AttributeBuilder.build("custom2", list("123", "456")));

        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Update: replace custom1, add 789 and remove 123 from custom2
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("custom1", "abc"));
        modifications.add(AttributeDeltaBuilder.build("custom2", list("789"), list("123")));

        connector.updateDelta(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(USER_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("foo")), defaultGetOperation("custom1", "custom2"));

        assertEquals("abc", singleAttr(result, "custom1"));
        assertEquals(set("456", "789"), asSet(multiAttr(result, "custom2")));
    }

    // --- Helpers ---

    private Uid createTestUser(String name, String email, String firstName, String lastName) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        attrs.add(AttributeBuilder.buildEnabled(true));
        attrs.add(AttributeBuilder.buildPassword("password".toCharArray()));
        attrs.add(AttributeBuilder.build("email", email));
        attrs.add(AttributeBuilder.build("firstName", firstName));
        attrs.add(AttributeBuilder.build("lastName", lastName));
        return connector.create(USER_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
    }

    private Uid createTestGroup(String name) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        return connector.create(new ObjectClass("group"), attrs, new OperationOptionsBuilder().build());
    }
}
