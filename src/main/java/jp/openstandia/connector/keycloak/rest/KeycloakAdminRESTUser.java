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
import jp.openstandia.connector.keycloak.KeycloakUtils;
import jp.openstandia.connector.keycloak.common.Transformation;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.*;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

import static jp.openstandia.connector.keycloak.KeycloakUserHandler.*;
import static jp.openstandia.connector.keycloak.KeycloakUtils.*;
import static jp.openstandia.connector.keycloak.rest.KeycloakRESTUtils.checkCreateResult;
import static jp.openstandia.connector.keycloak.rest.KeycloakRESTUtils.checkDeleteResult;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;

/**
 * Keycloak client implementation for user object which uses Keycloak Admin REST client.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakAdminRESTUser implements KeycloakClient.User {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTUser.class);

    private final String instanceName;
    private final KeycloakConfiguration configuration;
    private Keycloak adminClient;

    public KeycloakAdminRESTUser(String instanceName, KeycloakConfiguration configuration, Keycloak adminClient) {
        this.instanceName = instanceName;
        this.configuration = configuration;
        this.adminClient = adminClient;
    }

    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    private UsersResource users(String realmName) {
        return realm(realmName).users();
    }

    @Override
    public Uid createUser(KeycloakSchema schema, String realmName, Set<Attribute> createAttributes)
            throws AlreadyExistsException {
        UserRepresentation newUser = toUserRep(schema, createAttributes);

        CredentialRepresentation credential = null;
        if (configuration.isPasswordResetAPIEnabled()) {
            List<CredentialRepresentation> credentials = newUser.getCredentials();
            if (credentials != null && credentials.size() == 1) {
                credential = credentials.get(0);
            }
            // Need to remove credentials when using password reset API for setting the password.
            newUser.setCredentials(null);
        }

        List<String> addGroupIds = newUser.getGroups();
        // Remove groups intentionally because keycloak expects group path list
        newUser.setGroups(null);

        Response res = users(realmName).create(newUser);

        String uuid = checkCreateResult(res, "createUser");

        // We need to call another API to update password and add/remove group for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Keycloak data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.

        updatePassword(realmName, uuid, credential, true);

        // Adding groups when creating a user is supported from 9.0.2.
        // https://github.com/keycloak/keycloak/pull/6886
        // But it requires group path list. So we don't use this API.
        // That's why we call another API here.
        if (addGroupIds != null) {
            for (String groupId : addGroupIds) {
                try {
                    users(realmName).get(uuid).joinGroup(groupId);
                } catch (NotFoundException e) {
                    LOGGER.warn("The group is not found already. Skipping join the user. groupId: {0}, userId: {1}, username: {2}",
                            groupId, uuid, newUser.getUsername());
                }
            }
        }

        return new Uid(uuid, new Name(newUser.getUsername()));
    }

    protected UserRepresentation toUserRep(KeycloakSchema schema, Set<Attribute> attributes) {
        UserRepresentation newUser = new UserRepresentation();

        for (Attribute attr : attributes) {
            if (attr.getName().equals(Name.NAME)) {
                newUser.setUsername(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ENABLE_NAME)) {
                newUser.setEnabled(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                List<CredentialRepresentation> credentials = new ArrayList<>();
                GuardedString password = AttributeUtil.getGuardedStringValue(attr);
                password.access(a -> {
                    String clearPassword = String.valueOf(a);
                    CredentialRepresentation passwordRep = new CredentialRepresentation();
                    passwordRep.setType(CredentialRepresentation.PASSWORD);
                    passwordRep.setTemporary(Boolean.FALSE);
                    passwordRep.setValue(clearPassword);

                    credentials.add(passwordRep);
                });
                newUser.setCredentials(credentials);

            } else if (attr.getName().equals(ATTR_EMAIL)) {
                newUser.setEmail(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_EMAIL_VERIFIED)) {
                newUser.setEmailVerified(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_FIRST_NAME)) {
                newUser.setFirstName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_LAST_NAME)) {
                newUser.setLastName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_GROUPS)) {
                // Keycloak expects the group list as group path list.
                // Because we set group id list here, we cant't use it for this API.
                // See createUser method.
                List<String> groups = attr.getValue().stream().map(a -> a.toString()).collect(Collectors.toList());
                newUser.setGroups(groups);

            } else {
                if (!schema.isUserSchema(attr)) {
                    throw new InvalidAttributeValueException(String.format("Keycloak doesn't support to set '%s' attribute of User",
                            attr.getName()));
                }
                if (schema.isMultiValuedUserSchema(attr)) {
                    Map<String, List<String>> attrs = newUser.getAttributes();
                    if (attrs == null) {
                        attrs = new HashMap();
                    }
                    attrs.put(attr.getName(), attr.getValue().stream().map(a -> a.toString()).collect(Collectors.toList()));

                } else {
                    newUser.singleAttribute(attr.getName(), AttributeUtil.getStringValue(attr));
                }
            }
        }

        return newUser;
    }

    private void updatePassword(String realmName, String userId, CredentialRepresentation credential, final Boolean permanent)
            throws InvalidAttributeValueException {
        if (credential == null) {
            return;
        }

        try {
            users(realmName).get(userId).resetPassword(credential);

        } catch (BadRequestException e) {
            InvalidAttributeValueException ex = new InvalidAttributeValueException("Password policy error in keycloak", e);
            ex.setAffectedAttributeNames(Arrays.asList(OperationalAttributes.PASSWORD_NAME));
            throw ex;
        }
    }

    @Override
    public void updateUser(KeycloakSchema schema, String realmName, Uid uid, Set<AttributeDelta> modifications,
                           OperationOptions options) throws UnknownUidException {
        UsersResource usersResource = users(realmName);
        UserRepresentation current;
        List<String> addGroupIds = new ArrayList<>();
        List<String> removeGroupIds = new ArrayList<>();
        Map<String, List<RoleRepresentation>> clientRolesToAdd = new HashMap<>();
        Map<String, List<RoleRepresentation>> clientRolesToRemove = new HashMap<>();
        CredentialRepresentation credential = null;

        try {
            UserResource user = usersResource.get(uid.getUidValue());
            current = user.toRepresentation();

            for (AttributeDelta delta : modifications) {
                if (delta.getName().equals(Uid.NAME)) {
                    // Keycloak doesn't support to modify 'id'
                    invalidSchema(delta.getName());

                } else if (delta.getName().equals(Name.NAME)) {
                    current.setUsername(AttributeDeltaUtil.getAsStringValue(delta));

                } else if (delta.getName().equals(ENABLE_NAME)) {
                    current.setEnabled(AttributeDeltaUtil.getBooleanValue(delta));

                } else if (delta.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                    List<CredentialRepresentation> credentials = new ArrayList<>();
                    GuardedString password = AttributeDeltaUtil.getGuardedStringValue(delta);
                    password.access(a -> {
                        String clearPassword = String.valueOf(a);
                        CredentialRepresentation passwordRep = new CredentialRepresentation();
                        passwordRep.setType(CredentialRepresentation.PASSWORD);
                        passwordRep.setTemporary(Boolean.FALSE);
                        passwordRep.setValue(clearPassword);

                        credentials.add(passwordRep);
                    });
                    current.setCredentials(credentials);

                } else if (delta.getName().equals(ATTR_EMAIL)) {
                    current.setEmail(toKeycloakValue(schema.userSchema, delta));

                } else if (delta.getName().equals(ATTR_EMAIL_VERIFIED)) {
                    current.setEmailVerified(AttributeDeltaUtil.getBooleanValue(delta));

                } else if (delta.getName().equals(ATTR_FIRST_NAME)) {
                    current.setFirstName(toKeycloakValue(schema.userSchema, delta));

                } else if (delta.getName().equals(ATTR_LAST_NAME)) {
                    current.setLastName(toKeycloakValue(schema.userSchema, delta));

                } else if (delta.getName().equals(ATTR_GROUPS)) {
                    if (delta.getValuesToAdd() != null) {
                        for (Object group : delta.getValuesToAdd()) {
                            addGroupIds.add(group.toString());
                        }
                    }
                    if (delta.getValuesToRemove() != null) {
                        for (Object group : delta.getValuesToRemove()) {
                            removeGroupIds.add(group.toString());
                        }
                    }

                } else if (delta.getName().equals(ATTR_ROLES)) {
                    if (delta.getValuesToAdd() != null) {
                        List<String> rolesToAddDelta = delta.getValuesToAdd().stream()
                                .map(r -> r.toString())
                                .collect(Collectors.toList());

                        clientRolesToAdd = Transformation.groupsToClientRoleMap(rolesToAddDelta,
                                "/",
                                0,
                                1,
                                realm(realmName));
                    }
                    if (delta.getValuesToRemove() != null) {
                        List<String> rolesToRemoveDelta = delta.getValuesToRemove().stream()
                                .map(r -> r.toString())
                                .collect(Collectors.toList());

                        clientRolesToRemove = Transformation.groupsToClientRoleMap(rolesToRemoveDelta,
                                "/",
                                0,
                                1,
                                realm(realmName));
                    }

                } else if (schema.isUserSchema(delta)) {
                    if (schema.isMultiValuedUserSchema(delta)) {
                        Map<String, List<String>> attrs = current.getAttributes();
                        if (attrs == null) {
                            attrs = new HashMap();
                        }
                        List<String> values = attrs.getOrDefault(delta.getName(), new ArrayList<>());
                        attrs.put(delta.getName(), values);

                        if (delta.getValuesToAdd() != null) {
                            for (Object v : delta.getValuesToAdd()) {
                                // TODO support more types
                                values.add(v.toString());
                            }
                        }

                        if (delta.getValuesToRemove() != null) {
                            for (Object v : delta.getValuesToRemove()) {
                                // TODO support more types
                                values.remove(v.toString());
                            }
                        }

                        current.setAttributes(attrs);

                    } else {
                        // TODO support more types
                        current.singleAttribute(delta.getName(), AttributeDeltaUtil.getStringValue(delta));
                    }

                } else {
                    invalidSchema(delta.getName());
                }
            }

            if (configuration.isPasswordResetAPIEnabled()) {
                List<CredentialRepresentation> credentials = current.getCredentials();
                if (credentials != null && credentials.size() == 1) {
                    credential = credentials.get(0);
                }
                // Need to remove credentials when using password reset API for setting the password.
                current.setCredentials(null);
            }

            // TODO Optimize update if no diff{
            user.update(current);

        } catch (NotFoundException e) {
            LOGGER.warn("Not found user when updating. uid: {0}", uid);
            throw new UnknownUidException(uid, USER_OBJECT_CLASS);
        }

        // We need to call another API to update password and add/remove group for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Keycloak data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.

        updatePassword(realmName, current.getId(), credential, true);

        for (String groupId : addGroupIds) {
            try {
                users(realmName).get(current.getId()).joinGroup(groupId);
            } catch (NotFoundException e) {
                LOGGER.warn("The group is not found already. Skipping join the user. groupId: {0}, userId: {1}, username: {2}",
                        groupId, current.getId(), current.getUsername());
            }
        }
        for (String groupId : removeGroupIds) {
            try {
                users(realmName).get(current.getId()).leaveGroup(groupId);
            } catch (NotFoundException e) {
                LOGGER.warn("The group is not found already. Skipping join the user. groupId: {0}, userId: {1}, username: {2}",
                        groupId, current.getId(), current.getUsername());
            }
        }

        if (!clientRolesToAdd.isEmpty()) {
            clientRolesToAdd.forEach((client, roleList) -> {
                try {
                    users(realmName).get(current.getId()).roles().clientLevel(client).add(roleList);
                } catch (NotFoundException e) {
                    LOGGER.warn("Assignment of client roles to user failed. client: {0}, role: {1}, userId: {2}, username: {3}",
                            client, roleList, current.getId(), current.getUsername());
                }
            });
        }

        if (!clientRolesToRemove.isEmpty()) {
            clientRolesToRemove.forEach((client, roleList) -> {
                try {
                    users(realmName).get(current.getId()).roles().clientLevel(client).remove(roleList);
                } catch (NotFoundException e) {
                    LOGGER.warn("Unassignment of client roles of client failed. client: {0}, role: {1}, userId: {2}, username: {3}",
                            client, roleList, current.getId(), current.getUsername());
                }
            });
        }
    }

    @Override
    public void deleteUser(KeycloakSchema schema, String realmName, Uid uid, OperationOptions options)
            throws UnknownUidException {
        try {
            Response response = users(realmName).delete(uid.getUidValue());

            checkDeleteResult(response, "deleteUser");

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Not found user when deleting. uid: {1}", instanceName, uid);
            throw new UnknownUidException(uid, USER_OBJECT_CLASS);
        }
    }

    @Override
    public void getUsers(KeycloakSchema schema, String realmName, ResultsHandler handler, OperationOptions options,
                         Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        UsersResource users = users(realmName);

        Integer count = users.count();

        int start = 0;
        int total = 0;

        while (total < count) {
            List<UserRepresentation> results = users.search("", start, queryPageSize, true);

            if (results.size() == 0) {
                break;
            }

            for (UserRepresentation rep : results) {
                handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));
            }

            total += results.size();
            start += queryPageSize;
        }
    }

    @Override
    public void getUser(KeycloakSchema schema, String realmName, Uid uid, ResultsHandler handler, OperationOptions options,
                        Set<String> attributesToGet, int queryPageSize) {
        try {
            UserRepresentation user = users(realmName).get(uid.getUidValue()).toRepresentation();

            boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

            handler.handle(toConnectorObject(schema, realmName, user, attributesToGet, allowPartialAttributeValues, queryPageSize));

        } catch (NotFoundException e) {
            // Don't throw UnknownUidException
            // The executeQuery should not indicate any error in this case. It should not throw any exception.
            // MidPoint will see empty result set and it will figure out that there is no such object.
            LOGGER.warn("[{0}] Unknown userId: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
            return;
        }
    }

    @Override
    public void getUser(KeycloakSchema schema, String realmName, Name name, ResultsHandler handler, OperationOptions options,
                        Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        UsersResource users = users(realmName);

        Integer count = users.count(name.getNameValue());

        int start = 0;
        int total = 0;

        while (total < count) {
            int end = start + queryPageSize;

            List<UserRepresentation> results = users.search(name.getNameValue(), start, end, true);

            if (results.size() == 0) {
                break;
            }

            for (UserRepresentation u : results) {
                if (u.getUsername().equalsIgnoreCase(name.getNameValue())) {
                    // Found
                    handler.handle(toConnectorObject(schema, realmName, u, attributesToGet, allowPartialAttributeValues, queryPageSize));
                    return;
                }
            }

            total += results.size();
            start = end + 1;
        }

        // NotFound
        LOGGER.warn("[{0}] Unknown username: {1}", instanceName, name.getNameValue());
    }

    private ConnectorObject toConnectorObject(KeycloakSchema schema, String realmName, UserRepresentation user,
                                              Set<String> attributesToGet, boolean allowPartialAttributeValues, int queryPageSize) {
        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(USER_OBJECT_CLASS)
                // Always returns "id"
                .setUid(user.getId())
                // Always returns "username"
                .setName(user.getUsername());

        // Metadata
        if (shouldReturn(attributesToGet, ENABLE_NAME)) {
            builder.addAttribute(AttributeBuilder.buildEnabled(user.isEnabled()));
        }
        if (shouldReturn(attributesToGet, ATTR_CREATED_TIMESTAMP)) {
            builder.addAttribute(ATTR_CREATED_TIMESTAMP, KeycloakUtils.toZoneDateTime(user.getCreatedTimestamp()));
        }
        if (shouldReturn(attributesToGet, ATTR_EMAIL)) {
            builder.addAttribute(ATTR_EMAIL, user.getEmail());
        }
        if (shouldReturn(attributesToGet, ATTR_EMAIL_VERIFIED)) {
            builder.addAttribute(ATTR_EMAIL_VERIFIED, user.isEmailVerified());
        }
        if (shouldReturn(attributesToGet, ATTR_FIRST_NAME)) {
            builder.addAttribute(ATTR_FIRST_NAME, user.getFirstName());
        }
        if (shouldReturn(attributesToGet, ATTR_LAST_NAME)) {
            builder.addAttribute(ATTR_LAST_NAME, user.getLastName());
        }

        Map<String, List<String>> attributes = user.getAttributes();
        if (attributes != null) {
            for (Map.Entry<String, List<String>> entry : user.getAttributes().entrySet()) {
                String a = entry.getKey();
                AttributeInfo attributeInfo = schema.getUserSchema(a);

                if (attributeInfo == null) {
                    LOGGER.ok("[{0}] Ignored. \"{1}\" is not defined in the user schema.", instanceName, a);
                    continue;
                }

                if (shouldReturn(attributesToGet, attributeInfo.getName())) {
                    builder.addAttribute(toConnectorAttribute(attributeInfo, entry));
                }
            }
        }

        if (allowPartialAttributeValues) {
            // Suppress fetching groups
            LOGGER.ok("[{0}] Suppress fetching groups because return partial attribute values is requested", instanceName);

            AttributeBuilder ab = new AttributeBuilder();
            ab.setName(ATTR_GROUPS).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
            ab.addValue(Collections.EMPTY_LIST);
            builder.addAttribute(ab.build());

            // Suppress fetching roles
            LOGGER.ok("[{0}] Suppress fetching groups because return partial attribute values is requested", instanceName);

            AttributeBuilder ab_roles = new AttributeBuilder();
            ab_roles.setName(ATTR_ROLES).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
            ab_roles.addValue(Collections.EMPTY_LIST);
            builder.addAttribute(ab_roles.build());
        } else {
            if (attributesToGet == null) {
                // Suppress fetching groups default
                LOGGER.ok("[{0}] Suppress fetching groups because returned by default is true", instanceName);

                // Suppress fetching roles default
                LOGGER.ok("[{0}] Suppress fetching roles because returned by default is true", instanceName);

            } else {
                if (shouldReturn(attributesToGet, ATTR_GROUPS)) {
                    // Fetch groups
                    LOGGER.ok("[{0}] Fetching groups because attributes to get is requested", instanceName);

                    List<GroupRepresentation> groups = users(realmName).get(user.getId()).groups();
                    builder.addAttribute(ATTR_GROUPS, groups.stream().map(g -> g.getId()).collect(Collectors.toList()));
                }

                if (shouldReturn(attributesToGet, ATTR_ROLES)) {
                    // Fetch roles
                    LOGGER.ok("[{0}] Fetching roles because attributes to get is requested", instanceName);

                    Map<String, ClientMappingsRepresentation> roles = users(realmName).get(user.getId()).roles().getAll().getClientMappings();

                    if(roles != null) {
                        List<String> roleMappings = new ArrayList<>();

                        roles.forEach((client, roleRep) -> {
                            roleRep.getMappings().stream().forEach(m -> {
                                roleMappings.add(roleRep.getId() + "/" + m.getName());
                            });
                        });

                        builder.addAttribute(ATTR_ROLES, roleMappings);
                    }
                }
            }
        }

        return builder.build();
    }
}
