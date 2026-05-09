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

import jp.openstandia.connector.keycloak.KeycloakGroupHandler;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.jupiter.api.Test;

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

    // --- Helpers ---

    private Uid createTestGroup(String name) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        return connector.create(GROUP_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
    }
}
