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
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.Schema;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SchemaIT extends AbstractIntegrationTest {

    @Test
    void schema() {
        Schema schema = connector.schema();
        assertNotNull(schema);
        // user, group, client, clientRole, realmRole
        assertEquals(5, schema.getObjectClassInfo().size());
    }

    @Test
    void user() {
        Schema schema = connector.schema();

        ObjectClassInfo userInfo = schema.getObjectClassInfo().stream()
                .filter(o -> o.getType().equals("user"))
                .findFirst()
                .orElseThrow();

        // Uid, Name, __PASSWORD__, __ENABLE__, email, emailVerified, firstName, lastName,
        // createdTimestamp, groups, realmRoles, clientRoles = 12
        assertEquals(12, userInfo.getAttributeInfo().size());
    }

    @Test
    void userWithAttributes() {
        KeycloakConfiguration conf = newConfiguration();
        conf.setUserAttributes("custom1,custom2:multivalued");
        ConnectorFacade connector = newFacade(conf);

        Schema schema = connector.schema();

        ObjectClassInfo userInfo = schema.getObjectClassInfo().stream()
                .filter(o -> o.getType().equals("user"))
                .findFirst()
                .orElseThrow();

        // 12 + 2 custom attributes = 14
        assertEquals(14, userInfo.getAttributeInfo().size());
    }

    @Test
    void group() {
        Schema schema = connector.schema();

        ObjectClassInfo groupInfo = schema.getObjectClassInfo().stream()
                .filter(o -> o.getType().equals("group"))
                .findFirst()
                .orElseThrow();

        // Uid, Name, path, parentGroup = 4
        assertEquals(4, groupInfo.getAttributeInfo().size());
    }

    @Test
    void groupWithAttributes() {
        KeycloakConfiguration conf = newConfiguration();
        conf.setGroupAttributes("custom1,custom2:multivalued");
        ConnectorFacade connector = newFacade(conf);

        Schema schema = connector.schema();

        ObjectClassInfo groupInfo = schema.getObjectClassInfo().stream()
                .filter(o -> o.getType().equals("group"))
                .findFirst()
                .orElseThrow();

        // 4 + 2 custom attributes = 6
        assertEquals(6, groupInfo.getAttributeInfo().size());
    }

    @Test
    void client() {
        Schema schema = connector.schema();

        ObjectClassInfo clientInfo = schema.getObjectClassInfo().stream()
                .filter(o -> o.getType().equals("client"))
                .findFirst()
                .orElseThrow();

        // Uid, Name, protocol, redirectUris, name, description, adminUrl, secret,
        // publicClient, standardFlowEnabled, implicitFlowEnabled, directAccessGrantsEnabled,
        // serviceAccountsEnabled, bearerOnly, baseUrl, rootUrl, origin, webOrigins,
        // authorizationServicesEnabled, __ENABLE__, attributes = 21
        assertEquals(21, clientInfo.getAttributeInfo().size());
    }

    @Test
    void clientRole() {
        Schema schema = connector.schema();

        ObjectClassInfo clientRoleInfo = schema.getObjectClassInfo().stream()
                .filter(o -> o.getType().equals("clientRole"))
                .findFirst()
                .orElseThrow();

        // Uid, Name, description, attributes = 4
        assertEquals(4, clientRoleInfo.getAttributeInfo().size());
    }

    @Test
    void realmRole() {
        Schema schema = connector.schema();

        ObjectClassInfo realmRoleInfo = schema.getObjectClassInfo().stream()
                .filter(o -> o.getType().equals("realmRole"))
                .findFirst()
                .orElseThrow();

        // Uid, Name, description, attributes = 4
        assertEquals(4, realmRoleInfo.getAttributeInfo().size());
    }
}
