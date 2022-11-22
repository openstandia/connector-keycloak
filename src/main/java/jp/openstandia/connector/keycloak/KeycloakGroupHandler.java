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
package jp.openstandia.connector.keycloak;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.objects.*;

import java.util.Set;

import static jp.openstandia.connector.keycloak.KeycloakUtils.createFullAttributesToGet;

/**
 * Handle keycloak group object.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakGroupHandler extends AbstractKeycloakHandler {

    public static final ObjectClass GROUP_OBJECT_CLASS = new ObjectClass("group");

    private static final Log LOGGER = Log.getLog(KeycloakGroupHandler.class);

    // Unique and changeable within the keycloak realm
    private static final String ATTR_GROUP_NAME = "name";

    // Unique and unchangeable within the keycloak realm.
    // Don't use "id" here because it conflicts midpoint side.
    public static final String ATTR_GROUP_ID = "groupId";

    // read-only
    public static final String ATTR_PATH = "path";

    // Association
    public static final String ATTR_PARENT_GROUP = "parentGroup";
    public static final String ATTR_SUB_GROUPS = "subGroups";

    //Association
    public static final String ATTR_GROUP_ROLES = "groupRoles";

    public KeycloakGroupHandler(String instanceName, KeycloakConfiguration configuration, KeycloakClient client,
                                KeycloakSchema schema) {
        super(instanceName, configuration, client, schema);
    }

    public static ObjectClassInfo getGroupSchema(String[] attributes) {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(GROUP_OBJECT_CLASS.getObjectClassValue());

        // __UID__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Uid.NAME)
                .setRequired(false) // Must be optional. It is not present for create operations
                .setCreateable(false)
                .setUpdateable(false)
                .setNativeName(ATTR_GROUP_ID)
                .build());

        // __NAME__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true)
                .setUpdateable(true)
                .setNativeName(ATTR_GROUP_NAME)
                .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                .build());

        // path(read-only)
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_PATH)
                .setRequired(false)
                .setCreateable(false)
                .setUpdateable(false)
                .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                .build());

        // Attributes
        for (String attr : attributes) {
            String attrName;
            boolean multivalued = false;

            if (attr.contains(":")) {
                String[] metadata = attr.split(":");
                attrName = metadata[0];
                multivalued = metadata[1].equalsIgnoreCase("multivalued");
            } else {
                attrName = attr;
            }
            builder.addAttributeInfo(
                    AttributeInfoBuilder.define(attrName)
                            .setRequired(false)
                            .setUpdateable(true)
                            .setMultiValued(multivalued)
                            .build()
            );
        }

        // Association
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_PARENT_GROUP)
                .setMultiValued(false)
                .setReturnedByDefault(false)
                .build());

        // Association
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_GROUP_ROLES)
                .setMultiValued(true)
                .setReturnedByDefault(false)
                .build());

        ObjectClassInfo groupSchemaInfo = builder.build();

        LOGGER.info("The constructed Group core schema: {0}", groupSchemaInfo);

        return groupSchemaInfo;
    }

    /**
     * @param attributes
     * @return
     * @throws AlreadyExistsException Object with the specified _NAME_ already exists.
     *                                Or there is a similar violation in any of the object attributes that
     *                                cannot be distinguished from AlreadyExists situation.
     */
    @Override
    public Uid create(Set<Attribute> attributes) throws AlreadyExistsException {
        return client.group().createGroup(schema, configuration.getTargetRealmName(), attributes);
    }

    /**
     * @param uid
     * @param modifications
     * @param options
     * @return
     */
    @Override
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        client.group().updateGroup(schema, configuration.getTargetRealmName(), uid, modifications, options);

        return null;
    }

    /**
     * @param uid
     * @param options
     */
    @Override
    public void delete(Uid uid, OperationOptions options) {
        client.group().deleteGroup(schema, configuration.getTargetRealmName(), uid, options);
    }

    /**
     * @param filter
     * @param resultsHandler
     * @param options
     */
    @Override
    public void query(KeycloakFilter filter,
                      ResultsHandler resultsHandler, OperationOptions options) {
        // Create full attributesToGet by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET
        Set<String> attributesToGet = createFullAttributesToGet(schema.groupSchema, options);

        if (filter == null) {
            client.group().getGroups(schema, configuration.getTargetRealmName(),
                    resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
        } else {
            if (filter.isByUid()) {
                client.group().getGroup(schema, configuration.getTargetRealmName(), filter.uid,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            } else {
                client.group().getGroup(schema, configuration.getTargetRealmName(), filter.name,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            }
        }
    }
}
