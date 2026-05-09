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

import jp.openstandia.connector.keycloak.KeycloakConfiguration;
import jp.openstandia.connector.keycloak.KeycloakUserHandler;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.jupiter.api.Test;

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
