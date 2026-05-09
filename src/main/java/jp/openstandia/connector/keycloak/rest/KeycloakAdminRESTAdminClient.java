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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.fasterxml.jackson.jakarta.rs.json.JacksonXmlBindJsonProvider;
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
    private final KeycloakAdminRESTRealmRole realmRole;
    private Keycloak adminClient;

    public KeycloakAdminRESTAdminClient(String instanceName, KeycloakConfiguration configuration) {
        this.instanceName = instanceName;
        this.cofiguration = configuration;

        // Force RESTEasy's RuntimeDelegate implementation.
        //
        // ConnId's BundleClassLoader uses child-first class loading for classes, but
        // ServiceLoader (used by RuntimeDelegate.getInstance()) discovers providers from
        // all classloader entries including the parent (MidPoint's Spring Boot ClassLoader).
        // MidPoint 4.8+ bundles Apache CXF, whose RuntimeDelegateImpl is found by ServiceLoader
        // and is incompatible with RESTEasy, causing:
        //   ServiceConfigurationError: RuntimeDelegateImpl not a subtype
        //
        // Verified behavior across MidPoint versions:
        // - 4.0/4.4: getInstance() returns RESTEasy (CXF not present in parent classloader)
        // - 4.8/4.10: getInstance() throws ServiceConfigurationError (CXF found but incompatible)
        // In all cases, unconditional setInstance() is safe and ensures RESTEasy is used.
        RuntimeDelegate.setInstance(new ResteasyProviderFactoryImpl());

        ResteasyClientBuilder resteasyClientBuilder = new ResteasyClientBuilderImpl();
        resteasyClientBuilder.connectionPoolSize(20);
        resteasyClientBuilder.connectTimeout(configuration.getHttpConnectTimeoutInMilliseconds(), java.util.concurrent.TimeUnit.MILLISECONDS);
        resteasyClientBuilder.readTimeout(configuration.getHttpReadTimeoutInMilliseconds(), java.util.concurrent.TimeUnit.MILLISECONDS);
        resteasyClientBuilder.connectionCheckoutTimeout(5, java.util.concurrent.TimeUnit.SECONDS);

        // Register a Jackson JSON provider with a pre-configured ObjectMapper.
        //
        // Normally, keycloak-admin-client uses its own JacksonProvider (which extends
        // ResteasyJackson2Provider) to configure ObjectMapper with NON_NULL and
        // FAIL_ON_UNKNOWN_PROPERTIES=false for cross-version compatibility.
        // See: https://www.keycloak.org/securing-apps/admin-client
        //
        // However, ResteasyJackson2Provider has a field initializer that calls
        // ObjectMapper.findAndRegisterModules(), which uses Java ServiceLoader.
        // In MidPoint's ConnId BundleClassLoader environment, ServiceLoader discovers
        // Jackson modules from MidPoint's parent classloader (Spring Boot LaunchedClassLoader)
        // that are incompatible with the connector's Jackson version, causing:
        //   ServiceConfigurationError: ParameterNamesModule not a subtype
        //
        // To avoid this, we exclude resteasy-jackson2-provider from dependencies and
        // register JacksonXmlBindJsonProvider directly with a safe ObjectMapper that
        // does not call findAndRegisterModules(). The ObjectMapper settings match
        // Keycloak's JacksonProvider: NON_NULL and FAIL_ON_UNKNOWN_PROPERTIES=false.
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        resteasyClientBuilder.register(new JacksonXmlBindJsonProvider(
                mapper, JacksonXmlBindJsonProvider.DEFAULT_ANNOTATIONS));

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
        this.realmRole = new KeycloakAdminRESTRealmRole(instanceName, configuration, adminClient);
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
    public RealmRole realmRole() {
        return realmRole;
    }

    @Override
    public void close() {
        adminClient.close();
    }
}
