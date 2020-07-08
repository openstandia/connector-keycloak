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
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.GroupRepresentation;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

import static jp.openstandia.connector.keycloak.KeycloakGroupHandler.*;
import static jp.openstandia.connector.keycloak.KeycloakUtils.*;
import static jp.openstandia.connector.keycloak.rest.KeycloakRESTUtils.checkCreateResult;

/**
 * Keycloak client implementation for group object which uses Keycloak Admin REST client.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakAdminRESTGroup implements KeycloakClient.Group {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTGroup.class);

    private final String instanceName;
    private final KeycloakConfiguration configuration;
    private Keycloak adminClient;

    public KeycloakAdminRESTGroup(String instanceName, KeycloakConfiguration configuration, Keycloak adminClient) {
        this.instanceName = instanceName;
        this.configuration = configuration;
        this.adminClient = adminClient;
    }

    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    private GroupsResource groups(String realmName) {
        return realm(realmName).groups();
    }

    @Override
    public Uid createGroup(KeycloakSchema schema, String realmName, Set<Attribute> createAttributes) throws AlreadyExistsException {
        GroupRepresentation rep = toGroupRep(schema, createAttributes);

        Response res;

        // We use "path" field ad temporary store.
        // Don't forget clear it before submitting.
        String parentId = rep.getPath();
        if (parentId != null) {
            rep.setPath(null);

            // Keycloak creates sub group with parent group
            res = groups(realmName).group(parentId).subGroup(rep);
        } else {
            res = groups(realmName).add(rep);
        }

        String uuid = checkCreateResult(res, "createGroup");

        return new Uid(uuid, new Name(rep.getName()));
    }

    protected GroupRepresentation toGroupRep(KeycloakSchema schema, Set<Attribute> attributes) {
        GroupRepresentation newGroup = new GroupRepresentation();

        for (Attribute attr : attributes) {
            if (attr.getName().equals(Name.NAME)) {
                newGroup.setName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_PARENT_GROUP)) {
                // We use "path" field ad temporary store.
                // Don't forget clear it before submitting.
                newGroup.setPath(AttributeUtil.getAsStringValue(attr));

            } else {
                if (!schema.isGroupSchema(attr)) {
                    throw new InvalidAttributeValueException(String.format("Keycloak doesn't support to set '%s' attribute of Group",
                            attr.getName()));
                }
                if (schema.isMultiValuedGroupSchema(attr)) {
                    Map<String, List<String>> attrs = newGroup.getAttributes();
                    if (attrs == null) {
                        attrs = new HashMap();
                    }
                    attrs.put(attr.getName(), attr.getValue().stream().map(a -> a.toString()).collect(Collectors.toList()));

                } else {
                    newGroup.singleAttribute(attr.getName(), AttributeUtil.getStringValue(attr));
                }
            }
        }

        return newGroup;
    }

    @Override
    public void updateGroup(KeycloakSchema schema, String realmName, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException {
        GroupsResource resource = groups(realmName);
        GroupRepresentation current;
        String newParentGroupId = null;

        try {
            GroupResource group = resource.group(uid.getUidValue());
            current = group.toRepresentation();

            for (AttributeDelta delta : modifications) {
                if (delta.getName().equals(Uid.NAME)) {
                    // Keycloak doesn't support to modify 'id'
                    invalidSchema(delta.getName());

                } else if (delta.getName().equals(Name.NAME)) {
                    current.setName(AttributeDeltaUtil.getAsStringValue(delta));

                } else if (delta.getName().equals(ATTR_PARENT_GROUP)) {
                    newParentGroupId = AttributeDeltaUtil.getAsStringValue(delta);

                } else if (schema.isGroupSchema(delta)) {
                    if (schema.isMultiValuedGroupSchema(delta)) {
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

            // TODO Optimize update if no diff
            group.update(current);

        } catch (NotFoundException e) {
            LOGGER.warn("Not found group when updating. uid: {0}", uid);
            throw new UnknownUidException(uid, GROUP_OBJECT_CLASS);
        }

        // We need to call another API to add/remove parent group for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Keycloak data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.

        if (isTopGroup(current)) {
            if (newParentGroupId == null) {
                // From top => top
                // Do nothing!!
            } else {
                // From top => sub
                groups(realmName).group(newParentGroupId).subGroup(current);
            }
        } else {
            if (newParentGroupId == null) {
                // From sub => top level
                groups(realmName).add(current);
            } else {
                // From sub => sub with different parent
                groups(realmName).group(newParentGroupId).subGroup(current);
            }
        }
    }

    private boolean isTopGroup(GroupRepresentation rep) {
        String path = rep.getPath();
        long count = path.chars().filter(ch -> ch == '/').count();
        return count == 1;
    }

    @Override
    public void deleteGroup(KeycloakSchema schema, String realmName, Uid uid, OperationOptions options) throws UnknownUidException {
        try {
            groups(realmName).group(uid.getUidValue()).remove();

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Not found group when deleting. uid: {1}", instanceName, uid);
            throw new UnknownUidException(uid, GROUP_OBJECT_CLASS);
        }
    }

    @Override
    public void getGroups(KeycloakSchema schema, String realmName, ResultsHandler handler, OperationOptions options,
                          Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        GroupsResource groups = groups(realmName);

        Map<String, Long> countMap = groups.count();
        Long count = countMap.get("count");

        int start = 0;
        int total = 0;

        while (total < count) {
            List<GroupRepresentation> results = groups.groups("", start, queryPageSize, true);

            if (results.size() == 0) {
                break;
            }

            for (GroupRepresentation rep : results) {
                handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));
            }

            total += results.size();
            start += queryPageSize;
        }
    }

    @Override
    public void getGroup(KeycloakSchema schema, String realmName, Uid uid, ResultsHandler handler, OperationOptions options,
                         Set<String> attributesToGet, int queryPageSize) {
        try {
            GroupRepresentation rep = groups(realmName).group(uid.getUidValue()).toRepresentation();

            if (rep == null) {
                LOGGER.warn("[{0}] Unknown groupId: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
                return;
            }

            boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

            handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));

        } catch (NotFoundException e) {
            // Don't throw UnknownUidException
            // The executeQuery should not indicate any error in this case. It should not throw any exception.
            // MidPoint will see empty result set and it will figure out that there is no such object.
            LOGGER.warn("[{0}] Unknown groupId: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
            return;
        }
    }

    @Override
    public void getGroup(KeycloakSchema schema, String realmName, Name name, ResultsHandler handler, OperationOptions options,
                         Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        GroupsResource groups = groups(realmName);

        Map<String, Long> countMap = groups.count();
        Long count = countMap.get("count");

        int start = 0;
        int total = 0;

        while (total < count) {
            int end = start + queryPageSize;

            List<GroupRepresentation> results = groups.groups(name.getNameValue(), start, end, true);

            if (results.size() == 0) {
                break;
            }

            for (GroupRepresentation rep : results) {
                if (rep.getName().equalsIgnoreCase(name.getNameValue())) {
                    // Found
                    handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));
                    return;
                }
            }

            total += results.size();
            start = end + 1;
        }

        // NotFound
        LOGGER.warn("[{0}] Unknown group: {1}", instanceName, name.getNameValue());
    }


    private ConnectorObject toConnectorObject(KeycloakSchema schema, String realmName, GroupRepresentation rep,
                                              Set<String> attributesToGet, boolean allowPartialAttributeValues, int queryPageSize) {
        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(GROUP_OBJECT_CLASS)
                // Always returns "id"
                .setUid(rep.getId())
                // Always returns "name"
                .setName(rep.getName());

        builder.addAttribute(ATTR_PATH, rep.getPath());

        Map<String, List<String>> attributes = rep.getAttributes();
        if (attributes != null) {
            for (Map.Entry<String, List<String>> entry : rep.getAttributes().entrySet()) {
                String a = entry.getKey();
                AttributeInfo attributeInfo = schema.getGroupSchema(a);

                if (attributeInfo == null) {
                    LOGGER.ok("[{0}] Ignored. \"{1}\" is not defined in the group schema.", instanceName, a);
                    continue;
                }

                if (shouldReturn(attributesToGet, attributeInfo.getName())) {
                    builder.addAttribute(toConnectorAttribute(attributeInfo, entry));
                }
            }
        }

        if (allowPartialAttributeValues) {
            // Suppress fetching groups
            LOGGER.ok("[{0}] Suppress fetching parent group because return partial attribute values is requested", instanceName);

            AttributeBuilder ab = new AttributeBuilder();
            ab.setName(ATTR_PARENT_GROUP).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
            ab.addValue(Collections.EMPTY_LIST);
            builder.addAttribute(ab.build());
        } else {
            if (attributesToGet == null) {
                // Suppress fetching groups default
                LOGGER.ok("[{0}] Suppress fetching parent group because returned by default is true", instanceName);

            } else if (shouldReturn(attributesToGet, ATTR_PARENT_GROUP)) {
                // Fetch groups
                LOGGER.ok("[{0}] Fetching parent group because attributes to get is requested", instanceName);

                // Examples of the path value:
                // root group "foo" => /foo
                // sub group "bar" => /foo/bar
                String path = rep.getPath();
                String[] pathList = path.split("/");

                String parentGroupName = null;
                if (pathList.length > 2) {
                    parentGroupName = pathList[pathList.length - 2];
                }

                if (parentGroupName != null) {
                    String parentGroupId = findParentGroupByName(realmName, parentGroupName, rep.getId(), queryPageSize);
                    if (parentGroupId != null) {
                        builder.addAttribute(ATTR_PARENT_GROUP, parentGroupId);
                    }
                }
            }
        }

        return builder.build();
    }

    private String findParentGroupByName(String realmName, String parentGroupName, String groupId, int queryPageSize) {
        GroupsResource groups = groups(realmName);

        Map<String, Long> countMap = groups.count(parentGroupName);
        Long count = countMap.get("count");

        int start = 0;
        int total = 0;

        while (total < count) {
            int end = start + queryPageSize;

            List<GroupRepresentation> results = groups.groups(parentGroupName, start, end, true);

            if (results.size() == 0) {
                break;
            }

            for (GroupRepresentation rep : results) {
                if (rep.getName().equalsIgnoreCase(parentGroupName)) {
                    List<GroupRepresentation> subGroups = rep.getSubGroups();
                    if (subGroups != null) {
                        Optional<GroupRepresentation> sub = subGroups.stream().filter(g -> g.getId().equalsIgnoreCase(groupId)).findFirst();
                        if (sub.isPresent()) {
                            // Found
                            return rep.getId();
                        }
                    }
                }
            }

            total += results.size();
            start = end + 1;
        }

        // NotFound
        LOGGER.warn("[{0}] Not found parent group \"{1}\" for \"{2}\" ", instanceName, parentGroupName, groupId);

        return null;
    }
}
