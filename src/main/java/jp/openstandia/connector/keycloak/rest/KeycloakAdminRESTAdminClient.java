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
package jp.openstandia.connector.keycloak.rest;

import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import jp.openstandia.connector.keycloak.KeycloakClient;
import jp.openstandia.connector.keycloak.KeycloakConfiguration;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.jboss.resteasy.core.providerfactory.ResteasyProviderFactoryImpl;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.info.ServerInfoRepresentation;

import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.ext.RuntimeDelegate;

import static jp.openstandia.connector.keycloak.KeycloakUtils.getRootCause;

/**
 * Keycloak client implementation which uses Keycloak Admin REST client.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakAdminRESTAdminClient implements KeycloakClient {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTAdminClient.class);

    private final String instanceName;
    private final KeycloakConfiguration cofiguration;
    private final KeycloakAdminRESTUser user;
    private final KeycloakAdminRESTGroup group;
    private final KeycloakAdminRESTClient client;
    private final KeycloakAdminRESTClientRole clientRole;
    private Keycloak adminClient;

    public KeycloakAdminRESTAdminClient(String instanceName, KeycloakConfiguration configuration) {
        this.instanceName = instanceName;
        this.cofiguration = configuration;

        try {
            RuntimeDelegate.getInstance();
        } catch (Throwable t) {
            // Set the implementation directly as a workaround
            RuntimeDelegate.setInstance(new ResteasyProviderFactoryImpl());
        }

        ResteasyClientBuilder resteasyClientBuilder = new ResteasyClientBuilderImpl();
        resteasyClientBuilder.connectionPoolSize(20);

        // Register a named ContextResolver<ObjectMapper> so that JacksonJsonProvider.locateMapper()
        // uses our pre-configured mapper instead of calling ObjectMapper.findAndRegisterModules().
        // A lambda cannot be used here: RESTEasy resolves the generic type T of ContextResolver<T>
        // via Class.getGenericInterfaces(), which returns null for synthetic lambda classes and
        // causes: RESTEASY003920 / NullPointerException: "root" is null.
        // See KeycloakObjectMapperContextResolver for the full rationale.
        resteasyClientBuilder.register(new KeycloakObjectMapperContextResolver());

        // HTTP proxy configuration
        if (configuration.getHttpProxyHost() != null && configuration.getHttpProxyPort() != 0) {
            final String httpProxyHost = configuration.getHttpProxyHost();

            if (StringUtil.isNotBlank(configuration.getHttpProxyUser()) && configuration.getHttpProxyPassword() != null) {
                configuration.getHttpProxyPassword().access(s -> {
                    String httpProxyHostWithAuth = String.format("%s:%s@%s",
                            configuration.getHttpProxyUser(),
                            String.valueOf(s),
                            httpProxyHost);

                    resteasyClientBuilder.defaultProxy(httpProxyHostWithAuth, configuration.getHttpProxyPort(), "http");
                });
            } else {
                resteasyClientBuilder.defaultProxy(httpProxyHost, configuration.getHttpProxyPort(), "http");
            }
        }

        // Normalize the server URL once to avoid double-slash or /auth legacy issues.
        // getNormalizedServerUrl() strips trailing slashes and accepts sub-path URLs
        // such as https://iam.example.com/iam — the admin client will append
        // /realms/{realm}/... and /admin/realms/{realm}/... automatically.
        final String normalizedServerUrl = configuration.getNormalizedServerUrl();
        LOGGER.ok("Using Keycloak server URL: {0}", normalizedServerUrl);

        // grant_type=password mode
        if (configuration.getUsername() != null && configuration.getPassword() != null) {
            configuration.getPassword().access(s -> {
                adminClient = KeycloakBuilder.builder()
                        .serverUrl(normalizedServerUrl)
                        .realm(configuration.getRealmName())
                        .grantType("password")
                        .username(configuration.getUsername())
                        .password(String.valueOf(s))
                        .clientId(configuration.getClientId())
                        .resteasyClient(resteasyClientBuilder.build())
                        .build();
            });
        } else if (configuration.getClientSecret() != null) {
            configuration.getClientSecret().access(s -> {
                adminClient = KeycloakBuilder.builder()
                        .serverUrl(normalizedServerUrl)
                        .realm(configuration.getRealmName())
                        .grantType("client_credentials")
                        .clientId(configuration.getClientId())
                        .clientSecret(String.valueOf(s))
                        .resteasyClient(resteasyClientBuilder.build())
                        .build();
            });
        }

        this.user = new KeycloakAdminRESTUser(instanceName, configuration, adminClient);
        this.group = new KeycloakAdminRESTGroup(instanceName, configuration, adminClient);
        this.client = new KeycloakAdminRESTClient(instanceName, configuration, adminClient);
        this.clientRole = new KeycloakAdminRESTClientRole(instanceName, configuration, adminClient);
    }

    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    @Override
    public void test(String realmName) {
        try {
            Boolean enabled = adminClient.realm(realmName).toRepresentation().isEnabled();
            if (Boolean.TRUE != enabled) {
                throw new ConnectorException("The keycloak realm isn't active.");
            }
        } catch (ProcessingException e) {
            // Keycloak admin-client might throw exception due to version mismatch...

            Throwable rootCause = getRootCause(e);
            if (rootCause instanceof UnrecognizedPropertyException) {
                return;
            }
            throw new ConnectorException("Failed to test the Keycloak connector.", e);
        }
    }

    @Override
    public String getVersion() {
        // The /admin/serverinfo endpoint requires master-realm admin credentials.
        // When the connector is configured to authenticate against a non-master realm,
        // serverInfo().getInfo() may return a ServerInfoRepresentation where getSystemInfo()
        // is null (access denied or incomplete response).
        // In that case we fall back to a synthetic version string derived from the
        // admin-client library version so that KeycloakSchema.parseVersion() still works.
        try {
            ServerInfoRepresentation info = adminClient.serverInfo().getInfo();
            if (info != null && info.getSystemInfo() != null && info.getSystemInfo().getVersion() != null) {
                return info.getSystemInfo().getVersion();
            }
        } catch (Exception e) {
            LOGGER.warn("Could not retrieve server version via /admin/serverinfo (may require master realm access): {0}", e.getMessage());
        }
        // Fallback: return the keycloak-admin-client jar version so the connector
        // can still initialise and operate correctly against the target realm.
        String fallback = org.keycloak.admin.client.Keycloak.class.getPackage().getImplementationVersion();
        if (fallback == null) {
            fallback = "26.0.0";
        }
        LOGGER.ok("Falling back to library version: {0}", fallback);
        return fallback;
    }

    @Override
    public User user() {
        return user;
    }

    @Override
    public Group group() {
        return group;
    }

    @Override
    public Client client() {
        return client;
    }

    @Override
    public ClientRole clientRole() {
        return clientRole;
    }

    @Override
    public void close() {
        adminClient.close();
    }
}
