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
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.RoleRepresentation;

import jakarta.ws.rs.NotFoundException;
import java.util.*;

import static jp.openstandia.connector.keycloak.KeycloakRealmRoleHandler.*;
import static jp.openstandia.connector.keycloak.KeycloakUtils.*;

/**
 * Keycloak realmRole implementation for realmRole object which uses Keycloak Admin REST client.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakAdminRESTRealmRole implements KeycloakClient.RealmRole {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTRealmRole.class);

    private final String instanceName;
    private final KeycloakConfiguration configuration;
    private Keycloak adminClient;

    public KeycloakAdminRESTRealmRole(String instanceName, KeycloakConfiguration configuration, Keycloak adminClient) {
        this.instanceName = instanceName;
        this.configuration = configuration;
        this.adminClient = adminClient;
    }

    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    private RoleRepresentation realmRole(String realmName, Uid uid) {
        return realm(realmName).rolesById().getRole(uid.getUidValue());
    }

    private RoleRepresentation realmRole(String realmName, Name name) {
        return realm(realmName).roles().get(name.getNameValue()).toRepresentation();
    }

    @Override
    public Uid createRealmRole(KeycloakSchema schema, String realmName, Set<Attribute> createAttributes) throws AlreadyExistsException {
        RoleRepresentation rep = toRealmRoleRep(schema, createAttributes);

        if (rep.getName() == null) {
            throw new InvalidAttributeValueException("Must define name for the realmRole object");
        }

        RolesResource rolesResource = realm(realmName).roles();

        rolesResource.create(rep);

        RoleRepresentation created = rolesResource.get(rep.getName()).toRepresentation();

        // If the API doesn't support putting attributes when creating, we need to update the realmRole here
        if (rep.getAttributes() != null && !rep.getAttributes().isEmpty() && created.getAttributes().isEmpty()) {
            created.setAttributes(rep.getAttributes());
            realm(realmName).rolesById().updateRole(created.getId(), created);
        }

        return new Uid(created.getId(), new Name(created.getName()));
    }

    protected RoleRepresentation toRealmRoleRep(KeycloakSchema schema, Set<Attribute> attributes) {
        RoleRepresentation newRealmRole = new RoleRepresentation();
        newRealmRole.setClientRole(false);

        for (Attribute attr : attributes) {
            if (attr.getName().equals(Name.NAME)) {
                newRealmRole.setName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_DESCRIPTION)) {
                newRealmRole.setDescription(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_ATTRIBUTES)) {
                // Configured Attributes
                Map<String, List<String>> attrs = newRealmRole.getAttributes();
                if (attrs == null) {
                    attrs = new HashMap();
                }

                List<Object> values = attr.getValue();
                for (Object v : values) {
                    String kv = v.toString();
                    int index = kv.indexOf("=");
                    if (index <= 0) {
                        throw new InvalidAttributeValueException("The attribute is invalid format: " + kv);
                    }
                    String key = kv.substring(0, index);
                    String value = kv.substring(index + 1);

                    attrs.put(key, Arrays.asList(value.split("##")));
                }

                newRealmRole.setAttributes(attrs);
            }
        }

        return newRealmRole;
    }

    @Override
    public void updateRealmRole(KeycloakSchema schema, String realmName, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException {
        RoleRepresentation current = realmRole(realmName, uid);

        try {
            for (AttributeDelta delta : modifications) {
                if (delta.getName().equals(Name.NAME)) {
                    current.setName(AttributeDeltaUtil.getAsStringValue(delta));

                } else if (delta.getName().equals(ATTR_DESCRIPTION)) {
                    current.setDescription(AttributeDeltaUtil.getStringValue(delta));

                } else if (delta.getName().equals(ATTR_ATTRIBUTES)) {
                    // Configured Attributes
                    Map<String, List<String>> attrs = current.getAttributes();
                    if (attrs == null) {
                        attrs = new HashMap();
                    }

                    // First, we need to remove the attributes
                    if (delta.getValuesToRemove() != null) {
                        for (Object v : delta.getValuesToRemove()) {
                            String kv = v.toString();
                            int index = kv.indexOf("=");
                            if (index <= 0) {
                                throw new InvalidAttributeValueException("The attribute is invalid format: " + kv);
                            }
                            String key = kv.substring(0, index);

                            if (schema.realmRoleSchema != null && schema.realmRoleSchema.containsKey(key)) {
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

                            if (schema.realmRoleSchema != null && schema.realmRoleSchema.containsKey(key)) {
                                LOGGER.ok("Ignore putting attributes because it's configured attribute");
                                continue;
                            }

                            attrs.put(key, Arrays.asList(value.split("##")));
                        }
                    }

                    current.setAttributes(attrs);

                } else {
                    invalidSchema(delta.getName());
                }
            }

            // TODO Optimize update if no diff
            realm(realmName).rolesById().updateRole(current.getId(), current);

        } catch (NotFoundException e) {
            LOGGER.warn("Not found realmRole when updating. uid: {0}", uid);
            throw new UnknownUidException(uid, REALM_ROLE_OBJECT_CLASS);
        }

    }

    @Override
    public void deleteRealmRole(KeycloakSchema schema, String realmName, Uid uid, OperationOptions options) throws UnknownUidException {
        try {
            realm(realmName).rolesById().deleteRole(uid.getUidValue());

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Not found realmRole when deleting. uid: {1}", instanceName, uid);
            throw new UnknownUidException(uid, REALM_ROLE_OBJECT_CLASS);
        }
    }

    @Override
    public void getRealmRoles(KeycloakSchema schema, String realmName, ResultsHandler handler, OperationOptions options,
                               Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        RolesResource rolesResource = realm(realmName).roles();

        int start = 0;

        while (true) {
            List<RoleRepresentation> realmRoles = rolesResource.list(start, queryPageSize);

            if (realmRoles.isEmpty()) {
                break;
            }

            for (RoleRepresentation cr : realmRoles) {
                if (!handler.handle(toConnectorObject(schema, realmName, cr, attributesToGet, allowPartialAttributeValues, queryPageSize))) {
                    if (handler instanceof SearchResultsHandler) {
                        ((SearchResultsHandler) handler).handleResult(new SearchResult(null, 0, true));
                    }
                    return;
                }
            }

            start += realmRoles.size();

            if (realmRoles.size() < queryPageSize) {
                break;
            }
        }

        if (handler instanceof SearchResultsHandler) {
            ((SearchResultsHandler) handler).handleResult(new SearchResult(null, 0, true));
        }
    }

    @Override
    public void getRealmRole(KeycloakSchema schema, String realmName, Uid uid, ResultsHandler handler, OperationOptions options,
                              Set<String> attributesToGet, int queryPageSize) {
        try {
            RoleRepresentation rep = realmRole(realmName, uid);

            if (rep == null) {
                LOGGER.warn("[{0}] Unknown realmRole uuid: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
                return;
            }

            boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

            handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Unknown realmRole uuid: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
            return;
        }
    }

    @Override
    public void getRealmRole(KeycloakSchema schema, String realmName, Name name, ResultsHandler handler, OperationOptions options,
                              Set<String> attributesToGet, int queryPageSize) {
        try {
            RoleRepresentation rep = realmRole(realmName, name);

            if (rep == null) {
                LOGGER.warn("[{0}] Unknown realmRole name: {1}", instanceName, name.getNameValue());
                return;
            }

            boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

            handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Unknown realmRole name: {1}", instanceName, name.getNameValue());
            return;
        }
    }

    private ConnectorObject toConnectorObject(KeycloakSchema schema, String realmName, RoleRepresentation rep,
                                              Set<String> attributesToGet, boolean allowPartialAttributeValues, int queryPageSize) {
        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(REALM_ROLE_OBJECT_CLASS)
                // Always returns "id"
                .setUid(rep.getId())
                // Always returns "name"
                .setName(rep.getName());

        if (shouldReturn(attributesToGet, ATTR_DESCRIPTION)) {
            builder.addAttribute(ATTR_DESCRIPTION, rep.getDescription());
        }

        if (shouldReturn(attributesToGet, ATTR_ATTRIBUTES)) {
            Map<String, List<String>> attributes = rep.getAttributes();
            List<String> genericAttributes = new ArrayList<>();
            if (attributes != null) {
                for (Map.Entry<String, List<String>> entry : rep.getAttributes().entrySet()) {
                    String a = entry.getKey();

                    // Collect attributes as key=value formatted text
                    genericAttributes.add(String.format("%s=%s", a, String.join("##", entry.getValue())));
                }
            }

            builder.addAttribute(ATTR_ATTRIBUTES, genericAttributes);
        }

        return builder.build();
    }
}
