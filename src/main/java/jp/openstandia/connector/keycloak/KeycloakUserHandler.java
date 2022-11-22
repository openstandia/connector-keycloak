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
import org.identityconnectors.framework.common.objects.*;

import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static jp.openstandia.connector.keycloak.KeycloakUtils.createFullAttributesToGet;

/**
 * Handle keycloak user object.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakUserHandler extends AbstractKeycloakHandler {

    public static final ObjectClass USER_OBJECT_CLASS = new ObjectClass("user");

    private static final Log LOGGER = Log.getLog(KeycloakUserHandler.class);

    // The username for the user. Must be unique within the keycloak realm.
    // After the user is created, the username might be changed by the realm setting.
    public static final String ATTR_USERNAME = "username";

    // Unique and unchangeable within the keycloak realm.
    // Don't use "id" here because it conflicts midpoint side.
    public static final String ATTR_USER_ID = "userId";

    // Standard Attributes
    public static final String ATTR_EMAIL = "email";
    public static final String ATTR_EMAIL_VERIFIED = "emailVerified";
    public static final String ATTR_FIRST_NAME = "firstName";
    public static final String ATTR_LAST_NAME = "lastName";

    // Metadata
    public static final String ATTR_CREATED_TIMESTAMP = "createdTimestamp";

    // Association
    // groups is a list of keycloak group's id
    public static final String ATTR_GROUPS = "groups";

    // Association
    public static final String ATTR_ROLES = "roles";

    // Password
    public static final String ATTR_PASSWORD = "__PASSWORD__";
    public static final String ATTR_PASSWORD_PERMANENT = "password_permanent";

    // Enable
    public static final String ATTR_ENABLE = "__ENABLE__";

    public static final Set<String> NOT_USER_ATTRIBUTES = createNotUserAttributes();

    private static Set<String> createNotUserAttributes() {
        Set<String> attrs = new HashSet<>();
        attrs.add(Uid.NAME);
        attrs.add(Name.NAME);
        attrs.add(ATTR_CREATED_TIMESTAMP);
        attrs.add(ATTR_GROUPS);
        attrs.add(ATTR_ROLES);
        attrs.add(ATTR_PASSWORD_PERMANENT);
        attrs.addAll(OperationalAttributes.OPERATIONAL_ATTRIBUTE_NAMES);

        return Collections.unmodifiableSet(attrs);
    }

//    private final KeycloakAssociationHandler userGroupHandler;

    public KeycloakUserHandler(String instanceName, KeycloakConfiguration configuration, KeycloakClient client,
                               KeycloakSchema schema) {
        super(instanceName, configuration, client, schema);
//        this.userGroupHandler = new KeycloakAssociationHandler(configuration, client);
    }

    public static ObjectClassInfo getUserSchema(String[] attributes) {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(USER_OBJECT_CLASS.getObjectClassValue());

        // sub (__UID__)
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(Uid.NAME)
                        .setRequired(false) // Must be optional. It is not present for create operations
                        .setCreateable(false)
                        .setUpdateable(false)
                        .setNativeName(ATTR_USER_ID)
                        .build()
        );

        // username (__NAME__)
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(Name.NAME)
                        .setRequired(true)
                        .setUpdateable(true)
                        .setNativeName(ATTR_USERNAME)
                        .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                        .build()
        );

        // __ENABLE__ attribute
        builder.addAttributeInfo(OperationalAttributeInfos.ENABLE);

        // __PASSWORD__ attribute
        builder.addAttributeInfo(OperationalAttributeInfos.PASSWORD);
//        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_PASSWORD_PERMANENT)
//                .setType(Boolean.class)
//                .setReadable(false)
//                .setReturnedByDefault(false)
//                .build());

        // email
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_EMAIL)
                        .setRequired(false)
                        .setUpdateable(true)
                        .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                        .build()
        );
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_EMAIL_VERIFIED)
                        .setType(Boolean.class)
                        .setRequired(false)
                        .setUpdateable(true)
                        .build()
        );

        // firstName
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_FIRST_NAME)
                        .setRequired(false)
                        .setUpdateable(true)
                        .build()
        );

        // lastName
        builder.addAttributeInfo(
                AttributeInfoBuilder.define(ATTR_LAST_NAME)
                        .setRequired(false)
                        .setUpdateable(true)
                        .build()
        );

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

        // Metadata
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_CREATED_TIMESTAMP)
                .setType(ZonedDateTime.class)
                .setCreateable(false)
                .setUpdateable(false)
                .build());

        // Association
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_GROUPS)
                .setMultiValued(true)
                .setReturnedByDefault(false)
                .build());

        // Association
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_ROLES)
                .setMultiValued(true)
                .setReturnedByDefault(false)
                .build());

        ObjectClassInfo userSchemaInfo = builder.build();

        LOGGER.ok("The constructed User core schema: {0}", userSchemaInfo);

        return userSchemaInfo;
    }

    /**
     * @param attributes
     * @return
     */
    @Override
    public Uid create(Set<Attribute> attributes) {
        return client.user().createUser(schema, configuration.getTargetRealmName(), attributes);
    }

    /**
     * @param uid
     * @param modifications
     * @param options
     * @return
     */
    @Override
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        client.user().updateUser(schema, configuration.getTargetRealmName(), uid, modifications, options);

        return null;
    }

    /**
     * @param uid
     * @param options
     */
    @Override
    public void delete(Uid uid, OperationOptions options) {
        client.user().deleteUser(schema, configuration.getTargetRealmName(), uid, options);
    }


    @Override
    public void query(KeycloakFilter filter, ResultsHandler resultsHandler, OperationOptions options) {
        // Create full attributesToGet by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET
        Set<String> attributesToGet = createFullAttributesToGet(schema.userSchema, options);

        if (filter == null) {
            client.user().getUsers(schema, configuration.getTargetRealmName(),
                    resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
        } else {
            if (filter.isByUid()) {
                client.user().getUser(schema, configuration.getTargetRealmName(), filter.uid,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            } else {
                client.user().getUser(schema, configuration.getTargetRealmName(), filter.name,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            }
        }
    }
}
