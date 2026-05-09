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
import jp.openstandia.connector.keycloak.KeycloakConnector;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.userprofile.config.UPConfig;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public abstract class AbstractIntegrationTest {

    private static final String ADMIN_USER = "admin";
    private static final String ADMIN_PASSWORD = "admin";
    private static final String TEST_REALM = "test-realm";
    private static final String KEYCLOAK_VERSION = System.getProperty("keycloak.test.version", "26.0.8");
    private static final int KEYCLOAK_PORT = 8080;
    private static final Set<String> DEFAULT_CLIENTS = new HashSet<>(Arrays.asList(
            "account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"));

    protected static GenericContainer<?> keycloak;
    protected static String keycloakBaseUrl;

    protected ConnectorFacade connector;
    protected KeycloakConfiguration configuration;

    @BeforeAll
    static void startContainers() {
        if (keycloak != null && keycloak.isRunning()) {
            return;
        }
        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:" + KEYCLOAK_VERSION)
                .withExposedPorts(KEYCLOAK_PORT)
                // KC_BOOTSTRAP_ADMIN_* is for Keycloak 26+, KEYCLOAK_ADMIN* is for 24.x
                // Setting both is safe — the unused ones are simply ignored.
                .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
                .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
                .withEnv("KEYCLOAK_ADMIN", ADMIN_USER)
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", ADMIN_PASSWORD)
                .withCommand("start-dev")
                .waitingFor(Wait.forHttp("/realms/master")
                        .forPort(KEYCLOAK_PORT)
                        .forStatusCode(200)
                        .withStartupTimeout(java.time.Duration.ofMinutes(3)));
        keycloak.start();

        keycloakBaseUrl = String.format("http://%s:%d",
                keycloak.getHost(), keycloak.getMappedPort(KEYCLOAK_PORT));

        createTestRealm();
    }

    private static void createTestRealm() {
        try (Keycloak admin = KeycloakBuilder.builder()
                .serverUrl(keycloakBaseUrl)
                .realm("master")
                .grantType("password")
                .username(ADMIN_USER)
                .password(ADMIN_PASSWORD)
                .clientId("admin-cli")
                .build()) {

            RealmRepresentation realm = new RealmRepresentation();
            realm.setRealm(TEST_REALM);
            realm.setEnabled(true);
            realm.setEditUsernameAllowed(true);
            admin.realms().create(realm);

            // Enable unmanaged attributes so that custom user attributes are returned via API.
            // Since Keycloak 24, User Profile is enabled by default and new realms have
            // unmanagedAttributePolicy=null (strict mode), which filters out undefined attributes.
            UPConfig upConfig = admin.realm(TEST_REALM).users().userProfile().getConfiguration();
            upConfig.setUnmanagedAttributePolicy(UPConfig.UnmanagedAttributePolicy.ENABLED);
            admin.realm(TEST_REALM).users().userProfile().update(upConfig);
        }
    }

    // Container is stopped automatically by Testcontainers via JVM shutdown hook.
    // We do not stop it in @AfterAll because multiple test classes share the same container.

    protected KeycloakConfiguration newConfiguration() {
        KeycloakConfiguration conf = new KeycloakConfiguration();
        conf.setServerUrl(keycloakBaseUrl);
        conf.setUsername(ADMIN_USER);
        conf.setPassword(new GuardedString(ADMIN_PASSWORD.toCharArray()));
        conf.setClientId("admin-cli");
        conf.setRealmName("master");
        conf.setTargetRealmName(TEST_REALM);
        conf.setQueryPageSize(100);
        return conf;
    }

    protected ConnectorFacade newFacade(Configuration configuration) {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        APIConfiguration impl = TestHelpers.createTestConfiguration(KeycloakConnector.class, configuration);
        impl.getResultsHandlerConfiguration().setEnableAttributesToGetSearchResultsHandler(false);
        impl.getResultsHandlerConfiguration().setEnableNormalizingResultsHandler(false);
        impl.getResultsHandlerConfiguration().setEnableFilteredResultsHandler(false);
        return factory.newInstance(impl);
    }

    @BeforeEach
    void setUp() {
        cleanupTestRealm();

        this.configuration = newConfiguration();
        this.connector = newFacade(this.configuration);
    }

    private void cleanupTestRealm() {
        try (Keycloak admin = KeycloakBuilder.builder()
                .serverUrl(keycloakBaseUrl)
                .realm("master")
                .grantType("password")
                .username(ADMIN_USER)
                .password(ADMIN_PASSWORD)
                .clientId("admin-cli")
                .build()) {

            // Delete all users in test realm
            admin.realm(TEST_REALM).users().list(0, 1000).forEach(user ->
                    admin.realm(TEST_REALM).users().delete(user.getId()));

            // Delete all non-default groups
            admin.realm(TEST_REALM).groups().groups("", 0, 1000, true).forEach(group ->
                    admin.realm(TEST_REALM).groups().group(group.getId()).remove());

            // Delete non-default clients
            admin.realm(TEST_REALM).clients().findAll().forEach(client -> {
                if (!DEFAULT_CLIENTS.contains(client.getClientId())) {
                    admin.realm(TEST_REALM).clients().get(client.getId()).remove();
                }
            });
        }
    }

    @AfterEach
    void tearDown() {
        ConnectorFacadeFactory.getInstance().dispose();
    }

    // Utilities

    @SafeVarargs
    protected final <T> List<T> list(T... s) {
        return Arrays.stream(s).collect(Collectors.toList());
    }

    @SafeVarargs
    protected final <T> Set<T> set(T... s) {
        return Arrays.stream(s).collect(Collectors.toSet());
    }

    protected <T> Set<T> asSet(Collection<T> c) {
        return new HashSet<>(c);
    }

    protected String toPlain(GuardedString gs) {
        AtomicReference<String> plain = new AtomicReference<>();
        gs.access(c -> plain.set(String.valueOf(c)));
        return plain.get();
    }

    protected OperationOptions defaultGetOperation(String... explicit) {
        List<String> attrs = Arrays.stream(explicit).collect(Collectors.toList());
        attrs.add(OperationalAttributes.PASSWORD_NAME);
        attrs.add(OperationalAttributes.ENABLE_NAME);

        return new OperationOptionsBuilder()
                .setReturnDefaultAttributes(true)
                .setAttributesToGet(attrs)
                .setAllowPartialResults(true)
                .build();
    }

    protected OperationOptions defaultSearchOperation(String... explicit) {
        List<String> attrs = Arrays.stream(explicit).collect(Collectors.toList());
        attrs.add(OperationalAttributes.PASSWORD_NAME);
        attrs.add(OperationalAttributes.ENABLE_NAME);

        return new OperationOptionsBuilder()
                .setReturnDefaultAttributes(true)
                .setAttributesToGet(attrs)
                .setAllowPartialAttributeValues(true)
                .setPagedResultsOffset(1)
                .setPageSize(20)
                .build();
    }

    protected Object singleAttr(ConnectorObject connectorObject, String attrName) {
        Attribute attr = connectorObject.getAttributeByName(attrName);
        if (attr == null) {
            Assertions.fail(attrName + " is not contained in the connectorObject: " + connectorObject);
        }
        List<Object> value = attr.getValue();
        if (value == null || value.size() != 1) {
            Assertions.fail(attrName + " is not single value: " + value);
        }
        return value.get(0);
    }

    protected List<Object> multiAttr(ConnectorObject connectorObject, String attrName) {
        Attribute attr = connectorObject.getAttributeByName(attrName);
        if (attr == null) {
            Assertions.fail(attrName + " is not contained in the connectorObject: " + connectorObject);
        }
        List<Object> value = attr.getValue();
        if (value == null) {
            Assertions.fail(attrName + " is not multiple value: " + value);
        }
        return value;
    }

    protected boolean isIncompleteAttribute(Attribute attr) {
        if (attr == null) {
            return false;
        }
        return attr.getAttributeValueCompleteness().equals(AttributeValueCompleteness.INCOMPLETE);
    }
}
