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

import jp.openstandia.connector.keycloak.KeycloakClient;
import jp.openstandia.connector.keycloak.KeycloakConfiguration;
import jp.openstandia.connector.keycloak.KeycloakSchema;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

import static jp.openstandia.connector.keycloak.KeycloakClientHandler.*;
import static jp.openstandia.connector.keycloak.KeycloakUtils.*;
import static jp.openstandia.connector.keycloak.rest.KeycloakRESTUtils.checkCreateResult;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;

/**
 * Keycloak client implementation for client object which uses Keycloak Admin REST client.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakAdminRESTClient implements KeycloakClient.Client {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTClient.class);

    private final String instanceName;
    private final KeycloakConfiguration configuration;
    private Keycloak adminClient;

    public KeycloakAdminRESTClient(String instanceName, KeycloakConfiguration configuration, Keycloak adminClient) {
        this.instanceName = instanceName;
        this.configuration = configuration;
        this.adminClient = adminClient;
    }

    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    private ClientsResource clients(String realmName) {
        return realm(realmName).clients();
    }

    @Override
    public Uid createClient(KeycloakSchema schema, String realmName, Set<Attribute> createAttributes) throws AlreadyExistsException {
        ClientRepresentation rep = toClientRep(schema, createAttributes);

        Response res = clients(realmName).create(rep);

        String uuid = checkCreateResult(res, "createClient");

        return new Uid(uuid, new Name(rep.getClientId()));
    }

    protected ClientRepresentation toClientRep(KeycloakSchema schema, Set<Attribute> attributes) {
        ClientRepresentation newClient = new ClientRepresentation();

        for (Attribute attr : attributes) {
            if (attr.getName().equals(Name.NAME)) {
                newClient.setClientId(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ENABLE_NAME)) {
                newClient.setEnabled(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_PROTOCOL)) {
                newClient.setProtocol(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_NAME)) {
                newClient.setName(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_DESCRIPTION)) {
                newClient.setDescription(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_REDIRECT_URIS)) {
                newClient.setRedirectUris(attr.getValue().stream().map(Object::toString).collect(Collectors.toList()));

            } else if (attr.getName().equals(ATTR_ADMIN_URL)) {
                newClient.setAdminUrl(AttributeUtil.getStringValue(attr));

// openid-connect
            } else if (attr.getName().equals(ATTR_SECRET)) {
                GuardedString secret = AttributeUtil.getGuardedStringValue(attr);
                secret.access(a -> {
                    String clearPassword = String.valueOf(a);
                    newClient.setSecret(clearPassword);
                });

            } else if (attr.getName().equals(ATTR_PUBLIC_CLIENT)) {
                newClient.setPublicClient(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_STANDARD_FLOW_ENABLED)) {
                newClient.setStandardFlowEnabled(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_IMPLICIT_FLOW_ENABLED)) {
                newClient.setImplicitFlowEnabled(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_DIRECT_ACCESS_GRANTS_ENABLED)) {
                newClient.setDirectAccessGrantsEnabled(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_SERVICE_ACCOUNT_ENABLED)) {
                newClient.setServiceAccountsEnabled(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_BEARER_ONLY)) {
                newClient.setBearerOnly(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_BASE_URL)) {
                newClient.setBaseUrl(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_ROOT_URL)) {
                newClient.setRootUrl(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_ORIGIN)) {
                newClient.setOrigin(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_WEB_ORIGINS)) {
                newClient.setWebOrigins(attr.getValue().stream().map(Object::toString).collect(Collectors.toList()));

            } else if (attr.getName().equals(ATTR_AUTHORIZATION_SERVICES_ENABLED)) {
                newClient.setAuthorizationServicesEnabled(AttributeUtil.getBooleanValue(attr));

            } else if (schema.isClientSchema(attr) || attr.getName().equals(ATTR_ATTRIBUTES)) {
                // Configured Attributes
                Map<String, String> attrs = newClient.getAttributes();
                if (attrs == null) {
                    attrs = new HashMap();
                }

                if (schema.isClientSchema(attr)) {
                    // TODO support more types
                    attrs.put(attr.getName(), AttributeUtil.getStringValue(attr));

                } else {
                    List<Object> values = attr.getValue();
                    for (Object v : values) {
                        String kv = v.toString();
                        int index = kv.indexOf("=");
                        if (index <= 0) {
                            throw new InvalidAttributeValueException("The attribute is invalid format: " + kv);
                        }
                        String key = kv.substring(0, index);
                        String value = kv.substring(index + 1);

                        if (schema.clientSchema.containsKey(key)) {
                            LOGGER.ok("Ignore putting attributes because it's configured attribute");
                            continue;
                        }

                        attrs.put(key, value);
                    }
                }

                newClient.setAttributes(attrs);
            }
        }

        return newClient;
    }

    @Override
    public void updateClient(KeycloakSchema schema, String realmName, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException {
        ClientsResource resource = clients(realmName);
        ClientRepresentation current;

        try {
            ClientResource client = resource.get(uid.getUidValue());
            current = client.toRepresentation();

            for (AttributeDelta delta : modifications) {
                if (delta.getName().equals(Uid.NAME)) {
                    // Keycloak doesn't support to modify 'id'
                    invalidSchema(delta.getName());

                } else if (delta.getName().equals(Name.NAME)) {
                    current.setClientId(AttributeDeltaUtil.getAsStringValue(delta));

                } else if (delta.getName().equals(ENABLE_NAME)) {
                    current.setEnabled(AttributeDeltaUtil.getBooleanValue(delta));

                } else if (delta.getName().equals(ATTR_PROTOCOL)) {
                    current.setProtocol(AttributeDeltaUtil.getStringValue(delta));

                } else if (delta.getName().equals(ATTR_NAME)) {
                    current.setName(AttributeDeltaUtil.getStringValue(delta));

                } else if (delta.getName().equals(ATTR_DESCRIPTION)) {
                    current.setDescription(AttributeDeltaUtil.getStringValue(delta));

                } else if (delta.getName().equals(ATTR_REDIRECT_URIS)) {
                    current.setRedirectUris(mergeList(current.getRedirectUris(), delta));

                } else if (delta.getName().equals(ATTR_ADMIN_URL)) {
                    current.setAdminUrl(AttributeDeltaUtil.getStringValue(delta));

// openid-connect
                } else if (delta.getName().equals(ATTR_SECRET)) {
                    GuardedString secret = AttributeDeltaUtil.getGuardedStringValue(delta);
                    secret.access(a -> {
                        String clearPassword = String.valueOf(a);
                        current.setSecret(clearPassword);
                    });

                } else if (delta.getName().equals(ATTR_PUBLIC_CLIENT)) {
                    current.setPublicClient(AttributeDeltaUtil.getBooleanValue(delta));

                } else if (delta.getName().equals(ATTR_STANDARD_FLOW_ENABLED)) {
                    current.setStandardFlowEnabled(AttributeDeltaUtil.getBooleanValue(delta));

                } else if (delta.getName().equals(ATTR_IMPLICIT_FLOW_ENABLED)) {
                    current.setImplicitFlowEnabled(AttributeDeltaUtil.getBooleanValue(delta));

                } else if (delta.getName().equals(ATTR_DIRECT_ACCESS_GRANTS_ENABLED)) {
                    current.setDirectAccessGrantsEnabled(AttributeDeltaUtil.getBooleanValue(delta));

                } else if (delta.getName().equals(ATTR_SERVICE_ACCOUNT_ENABLED)) {
                    current.setServiceAccountsEnabled(AttributeDeltaUtil.getBooleanValue(delta));

                } else if (delta.getName().equals(ATTR_BEARER_ONLY)) {
                    current.setBearerOnly(AttributeDeltaUtil.getBooleanValue(delta));

                } else if (delta.getName().equals(ATTR_BASE_URL)) {
                    current.setBaseUrl(AttributeDeltaUtil.getStringValue(delta));

                } else if (delta.getName().equals(ATTR_ROOT_URL)) {
                    current.setRootUrl(AttributeDeltaUtil.getStringValue(delta));

                } else if (delta.getName().equals(ATTR_ORIGIN)) {
                    current.setOrigin(AttributeDeltaUtil.getStringValue(delta));

                } else if (delta.getName().equals(ATTR_WEB_ORIGINS)) {
                    current.setWebOrigins(mergeList(current.getWebOrigins(), delta));

                } else if (delta.getName().equals(ATTR_AUTHORIZATION_SERVICES_ENABLED)) {
                    current.setAuthorizationServicesEnabled(AttributeDeltaUtil.getBooleanValue(delta));

                } else if (schema.isClientSchema(delta) || delta.getName().equals(ATTR_ATTRIBUTES)) {
                    // Configured Attributes
                    Map<String, String> attrs = current.getAttributes();
                    if (attrs == null) {
                        attrs = new HashMap();
                    }

                    if (schema.isClientSchema(delta)) {
                        // TODO support more types
                        attrs.put(delta.getName(), AttributeDeltaUtil.getStringValue(delta));

                    } else {
                        // First, we need to remove the attributes
                        if (delta.getValuesToRemove() != null) {
                            for (Object v : delta.getValuesToRemove()) {
                                String kv = v.toString();
                                int index = kv.indexOf("=");
                                if (index <= 0) {
                                    throw new InvalidAttributeValueException("The attribute is invalid format: " + kv);
                                }
                                String key = kv.substring(0, index);

                                if (schema.clientSchema.containsKey(key)) {
                                    LOGGER.ok("Ignore removing attributes because it's configured attribute");
                                    continue;
                                }

                                attrs.remove(key);
                            }
                        }
                        if (delta.getValuesToAdd() != null) {
                            for (Object v : delta.getValuesToAdd()) {
                                String kv = v.toString();
                                int index = kv.indexOf("=");
                                if (index <= 0) {
                                    throw new InvalidAttributeValueException("The attribute is invalid format: " + kv);
                                }
                                String key = kv.substring(0, index);
                                String value = kv.substring(index + 1);

                                if (schema.clientSchema.containsKey(key)) {
                                    LOGGER.ok("Ignore putting attributes because it's configured attribute");
                                    continue;
                                }

                                attrs.put(key, value);
                            }
                        }
                    }

                    current.setAttributes(attrs);

                } else {
                    invalidSchema(delta.getName());
                }
            }

            // TODO Optimize update if no diff
            client.update(current);

        } catch (
                NotFoundException e) {
            LOGGER.warn("Not found client when updating. uid: {0}", uid);
            throw new UnknownUidException(uid, CLIENT_OBJECT_CLASS);
        }

    }

    @Override
    public void deleteClient(KeycloakSchema schema, String realmName, Uid uid, OperationOptions options) throws UnknownUidException {
        try {
            clients(realmName).get(uid.getUidValue()).remove();

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Not found client when deleting. uid: {1}", instanceName, uid);
            throw new UnknownUidException(uid, CLIENT_OBJECT_CLASS);
        }
    }

    @Override
    public void getClients(KeycloakSchema schema, String realmName, ResultsHandler handler, OperationOptions options,
                           Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        ClientsResource clients = clients(realmName);

        List<ClientRepresentation> results = clients.findAll();

        for (ClientRepresentation rep : results) {
            handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));
        }
    }

    @Override
    public void getClient(KeycloakSchema schema, String realmName, Uid uid, ResultsHandler handler, OperationOptions options,
                          Set<String> attributesToGet, int queryPageSize) {
        try {
            ClientRepresentation rep = clients(realmName).get(uid.getUidValue()).toRepresentation();

            if (rep == null) {
                LOGGER.warn("[{0}] Unknown client uuid: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
                return;
            }

            boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

            handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));

        } catch (NotFoundException e) {
            // Don't throw UnknownUidException
            // The executeQuery should not indicate any error in this case. It should not throw any exception.
            // MidPoint will see empty result set and it will figure out that there is no such object.
            LOGGER.warn("[{0}] Unknown client uuid: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
            return;
        }
    }

    @Override
    public void getClient(KeycloakSchema schema, String realmName, Name name, ResultsHandler handler, OperationOptions options,
                          Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        ClientsResource clients = clients(realmName);

        List<ClientRepresentation> results = clients.findByClientId(name.getNameValue());

        for (ClientRepresentation rep : results) {
            if (rep.getName().equalsIgnoreCase(name.getNameValue())) {
                // Found
                handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));
                return;
            }
        }

        // NotFound
        LOGGER.warn("[{0}] Unknown clientId: {1}", instanceName, name.getNameValue());
    }


    private ConnectorObject toConnectorObject(KeycloakSchema schema, String realmName, ClientRepresentation rep,
                                              Set<String> attributesToGet, boolean allowPartialAttributeValues, int queryPageSize) {
        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(CLIENT_OBJECT_CLASS)
                // Always returns "id"
                .setUid(rep.getId())
                // Always returns "name"
                .setName(rep.getClientId());

        if (shouldReturn(attributesToGet, ENABLE_NAME)) {
            builder.addAttribute(AttributeBuilder.buildEnabled(rep.isEnabled()));
        }
        if (shouldReturn(attributesToGet, ATTR_PROTOCOL)) {
            builder.addAttribute(ATTR_PROTOCOL, rep.getProtocol());
        }
        if (shouldReturn(attributesToGet, ATTR_REDIRECT_URIS)) {
            builder.addAttribute(ATTR_REDIRECT_URIS, rep.getRedirectUris());
        }
        if (shouldReturn(attributesToGet, ATTR_NAME)) {
            builder.addAttribute(ATTR_NAME, rep.getName());
        }
        if (shouldReturn(attributesToGet, ATTR_DESCRIPTION)) {
            builder.addAttribute(ATTR_DESCRIPTION, rep.getDescription());
        }
        if (shouldReturn(attributesToGet, ATTR_ADMIN_URL)) {
            builder.addAttribute(ATTR_ADMIN_URL, rep.getAdminUrl());
        }

        // openid-connect
        if (shouldReturn(attributesToGet, ATTR_SECRET)) {
            builder.addAttribute(ATTR_SECRET, rep.getSecret());
        }
        if (shouldReturn(attributesToGet, ATTR_PUBLIC_CLIENT)) {
            builder.addAttribute(ATTR_PUBLIC_CLIENT, rep.isPublicClient());
        }
        if (shouldReturn(attributesToGet, ATTR_STANDARD_FLOW_ENABLED)) {
            builder.addAttribute(ATTR_STANDARD_FLOW_ENABLED, rep.isStandardFlowEnabled());
        }
        if (shouldReturn(attributesToGet, ATTR_IMPLICIT_FLOW_ENABLED)) {
            builder.addAttribute(ATTR_IMPLICIT_FLOW_ENABLED, rep.isImplicitFlowEnabled());
        }
        if (shouldReturn(attributesToGet, ATTR_DIRECT_ACCESS_GRANTS_ENABLED)) {
            builder.addAttribute(ATTR_DIRECT_ACCESS_GRANTS_ENABLED, rep.isDirectAccessGrantsEnabled());
        }
        if (shouldReturn(attributesToGet, ATTR_SERVICE_ACCOUNT_ENABLED)) {
            builder.addAttribute(ATTR_SERVICE_ACCOUNT_ENABLED, rep.isServiceAccountsEnabled());
        }
        if (shouldReturn(attributesToGet, ATTR_BEARER_ONLY)) {
            builder.addAttribute(ATTR_BEARER_ONLY, rep.isBearerOnly());
        }
        if (shouldReturn(attributesToGet, ATTR_BASE_URL)) {
            builder.addAttribute(ATTR_BASE_URL, rep.getBaseUrl());
        }
        if (shouldReturn(attributesToGet, ATTR_ROOT_URL)) {
            builder.addAttribute(ATTR_ROOT_URL, rep.getRootUrl());
        }
        if (shouldReturn(attributesToGet, ATTR_ORIGIN)) {
            builder.addAttribute(ATTR_ORIGIN, rep.getOrigin());
        }
        if (shouldReturn(attributesToGet, ATTR_AUTHORIZATION_SERVICES_ENABLED)) {
            builder.addAttribute(ATTR_AUTHORIZATION_SERVICES_ENABLED, rep.getAuthorizationServicesEnabled());
        }

        Map<String, String> attributes = rep.getAttributes();
        List<String> genericAttributes = new ArrayList<>();
        if (attributes != null) {
            for (Map.Entry<String, String> entry : rep.getAttributes().entrySet()) {
                String a = entry.getKey();
                AttributeInfo attributeInfo = schema.getClientSchema(a);

                if (attributeInfo == null) {
                    LOGGER.ok("[{0}] Ignored. \"{1}\" is not defined in the client schema.", instanceName, a);

                    // Collect generic attributes as key=value formatted text
                    if (shouldReturn(attributesToGet, ATTR_ATTRIBUTES)) {
                        genericAttributes.add(String.format("%s=%s", a, entry.getValue()));
                    }
                    continue;
                }

                if (shouldReturn(attributesToGet, attributeInfo.getName())) {
                    builder.addAttribute(toConnectorAttributeSingleValue(attributeInfo, entry));
                }
            }
        }

        if (shouldReturn(attributesToGet, ATTR_ATTRIBUTES)) {
            builder.addAttribute(ATTR_ATTRIBUTES, genericAttributes);
        }

        return builder.build();
    }
}
