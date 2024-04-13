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
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import jakarta.ws.rs.NotFoundException;
import java.util.*;

import static jp.openstandia.connector.keycloak.KeycloakClientHandler.ATTR_CLIENT_UUID;
import static jp.openstandia.connector.keycloak.KeycloakClientRoleHandler.*;
import static jp.openstandia.connector.keycloak.KeycloakUtils.*;

/**
 * Keycloak clientRole implementation for clientRole object which uses Keycloak Admin REST client.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakAdminRESTClientRole implements KeycloakClient.ClientRole {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTClientRole.class);

    private final String instanceName;
    private final KeycloakConfiguration configuration;
    private Keycloak adminClient;

    public KeycloakAdminRESTClientRole(String instanceName, KeycloakConfiguration configuration, Keycloak adminClient) {
        this.instanceName = instanceName;
        this.configuration = configuration;
        this.adminClient = adminClient;
    }

    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    private RoleRepresentation clientRole(String realmName, Uid uid) {
        return realm(realmName).rolesById().getRole(uid.getUidValue());
    }

    private RoleRepresentation clientRole(String realmName, Name name) {
        String[] split = name.getNameValue().split("/");
        if (split.length != 2) {
            throw new InvalidAttributeValueException("Invalid name format for the clientRole. It must be <clientUUID>/<clientRoleName>. name: "
                    + name.getNameValue());
        }

        // Find by clientUUID and clientRoleName
        return realm(realmName).clients().get(split[0]).roles().get(split[1]).toRepresentation();
    }

    @Override
    public Uid createClientRole(KeycloakSchema schema, String realmName, Set<Attribute> createAttributes) throws AlreadyExistsException {
        RoleRepresentation rep = toClientRoleRep(schema, createAttributes);

        if (rep.getContainerId() == null || rep.getName() == null) {
            throw new InvalidAttributeValueException("Must define name for the clientRole object");
        }

        ClientResource clientResource = realm(realmName).clients().get(rep.getContainerId());

        clientResource.roles().create(rep);

        RoleRepresentation created = clientResource.roles().get(rep.getName()).toRepresentation();

        // If the API doesn't support putting attributes when creating, we need to update the clientRole here
        if (rep.getAttributes() != null && !rep.getAttributes().isEmpty() && created.getAttributes().isEmpty()) {
            created.setAttributes(rep.getAttributes());
            realm(realmName).rolesById().updateRole(created.getId(), created);
        }

        return new Uid(created.getId(), new Name(getUniqueName(created)));
    }

    protected RoleRepresentation toClientRoleRep(KeycloakSchema schema, Set<Attribute> attributes) {
        RoleRepresentation newClientRole = new RoleRepresentation();
        newClientRole.setClientRole(true);

        for (Attribute attr : attributes) {
            if (attr.getName().equals(Name.NAME)) {
                String name = AttributeUtil.getAsStringValue(attr);
                String[] split = name.split("/");

                if (split.length != 2) {
                    throw new InvalidAttributeValueException("Invalid clientRole name format." +
                            " It must be <clientUUID>/<clientRoleName>. name: " + name);
                }

                newClientRole.setContainerId(split[0]);
                newClientRole.setName(split[1]);

            } else if (attr.getName().equals(ATTR_DESCRIPTION)) {
                newClientRole.setDescription(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_CLIENT_UUID)) {
                newClientRole.setContainerId(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_ATTRIBUTES)) {
                // Configured Attributes
                Map<String, List<String>> attrs = newClientRole.getAttributes();
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

                newClientRole.setAttributes(attrs);
            }
        }

        return newClientRole;
    }

    @Override
    public void updateClientRole(KeycloakSchema schema, String realmName, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException {
        RoleRepresentation current = clientRole(realmName, uid);

        try {
            for (AttributeDelta delta : modifications) {
                if (delta.getName().equals(Name.NAME)) {
                    String name = AttributeDeltaUtil.getAsStringValue(delta);
                    String[] split = name.split("/");

                    if (split.length != 2) {
                        throw new InvalidAttributeValueException("Invalid clientRole name format." +
                                " It must be <clientUUID>/<clientRoleName>. name: " + name);
                    }

                    current.setContainerId(split[0]);
                    current.setName(split[1]);

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
            LOGGER.warn("Not found clientRole when updating. uid: {0}", uid);
            throw new UnknownUidException(uid, CLIENT_ROLE_OBJECT_CLASS);
        }

    }

    @Override
    public void deleteClientRole(KeycloakSchema schema, String realmName, Uid uid, OperationOptions options) throws UnknownUidException {
        try {
            realm(realmName).rolesById().deleteRole(uid.getUidValue());

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Not found clientRole when deleting. uid: {1}", instanceName, uid);
            throw new UnknownUidException(uid, CLIENT_ROLE_OBJECT_CLASS);
        }
    }

    @Override
    public void getClientRoles(KeycloakSchema schema, String realmName, ResultsHandler handler, OperationOptions options,
                               Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        RealmResource realmResource = realm(realmName);
        ClientsResource clientsResource = realmResource.clients();

        // TODO paging
        List<ClientRepresentation> allClients = clientsResource.findAll();

        allClients.stream().forEach(c -> {
            RolesResource rolesResource = clientsResource.get(c.getId()).roles();
            // TODO paging
            List<RoleRepresentation> clientRoles = rolesResource.list();

            clientRoles.stream().forEach(cr -> {
                handler.handle(toConnectorObject(schema, realmName, cr, attributesToGet, allowPartialAttributeValues, queryPageSize));
            });
        });
    }

    @Override
    public void getClientRole(KeycloakSchema schema, String realmName, Uid uid, ResultsHandler handler, OperationOptions options,
                              Set<String> attributesToGet, int queryPageSize) {
        try {
            RoleRepresentation rep = clientRole(realmName, uid);

            if (rep == null) {
                LOGGER.warn("[{0}] Unknown clientRole uuid: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
                return;
            }

            boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

            handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));

        } catch (NotFoundException e) {
            // Don't throw UnknownUidException
            // The executeQuery should not indicate any error in this case. It should not throw any exception.
            // MidPoint will see empty result set and it will figure out that there is no such object.
            LOGGER.warn("[{0}] Unknown clientRole uuid: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
            return;
        }
    }

    @Override
    public void getClientRole(KeycloakSchema schema, String realmName, Name name, ResultsHandler handler, OperationOptions options,
                              Set<String> attributesToGet, int queryPageSize) {
        try {
            RoleRepresentation rep = clientRole(realmName, name);

            if (rep == null) {
                LOGGER.warn("[{0}] Unknown clientRole name: {1}", instanceName, name.getNameValue());
                return;
            }

            boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

            handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));

        } catch (NotFoundException e) {
            // Don't throw UnknownUidException
            // The executeQuery should not indicate any error in this case. It should not throw any exception.
            // MidPoint will see empty result set and it will figure out that there is no such object.
            LOGGER.warn("[{0}] Unknown clientRole name: {1}", instanceName, name.getNameValue());
            return;
        }
    }

    /**
     * Returns unique name with "clientUUID/clientRoleName" format.
     *
     * @param rep
     * @return
     */
    private String getUniqueName(RoleRepresentation rep) {
        return rep.getContainerId() + "/" + rep.getName();
    }

    private ConnectorObject toConnectorObject(KeycloakSchema schema, String realmName, RoleRepresentation rep,
                                              Set<String> attributesToGet, boolean allowPartialAttributeValues, int queryPageSize) {
        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(CLIENT_ROLE_OBJECT_CLASS)
                // Always returns "id"
                .setUid(rep.getId())
                // Always returns "name"
                .setName(getUniqueName(rep));

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
