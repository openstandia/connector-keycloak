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
 * Handle keycloak realm role object.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakRealmRoleHandler extends AbstractKeycloakHandler {

    public static final ObjectClass REALM_ROLE_OBJECT_CLASS = new ObjectClass("realmRole");

    private static final Log LOGGER = Log.getLog(KeycloakRealmRoleHandler.class);

    // Unique and changeable within the keycloak realm.
    public static final String ATTR_NAME = "name";

    // Unique and unchangeable within the keycloak realm.
    // Don't use "id" here because it conflicts midpoint side.
    public static final String ATTR_REALM_ROLE_ID = "realmRoleId";

    public static final String ATTR_DESCRIPTION = "description";
    public static final String ATTR_ATTRIBUTES = "attributes";

    public KeycloakRealmRoleHandler(String instanceName, KeycloakConfiguration configuration, KeycloakClient client,
                                     KeycloakSchema schema) {
        super(instanceName, configuration, client, schema);
    }

    public static ObjectClassInfo getSchema(String[] attributes) {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(REALM_ROLE_OBJECT_CLASS.getObjectClassValue());

        // __UID__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Uid.NAME)
                .setRequired(false) // Must be optional. It is not present for create operations
                .setCreateable(false)
                .setUpdateable(false)
                .setNativeName(ATTR_REALM_ROLE_ID)
                .build());

        // __NAME__
        builder.addAttributeInfo(AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true)
                .setUpdateable(true)
                .setNativeName(ATTR_NAME)
                .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                .build());

        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_DESCRIPTION)
                .setRequired(false)
                .build());

        // Attributes
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_ATTRIBUTES)
                .setRequired(false)
                .setMultiValued(true)
                .build());

        ObjectClassInfo info = builder.build();

        LOGGER.info("The constructed realmRole core schema: {0}", info);

        return info;
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
        return client.realmRole().createRealmRole(schema, configuration.getTargetRealmName(), attributes);
    }

    /**
     * @param uid
     * @param modifications
     * @param options
     * @return
     */
    @Override
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        client.realmRole().updateRealmRole(schema, configuration.getTargetRealmName(), uid, modifications, options);

        return null;
    }

    /**
     * @param uid
     * @param options
     */
    @Override
    public void delete(Uid uid, OperationOptions options) {
        client.realmRole().deleteRealmRole(schema, configuration.getTargetRealmName(), uid, options);
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
        Set<String> attributesToGet = createFullAttributesToGet(schema.realmRoleSchema, options);

        if (filter == null) {
            client.realmRole().getRealmRoles(schema, configuration.getTargetRealmName(),
                    resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
        } else {
            if (filter.isByUid()) {
                client.realmRole().getRealmRole(schema, configuration.getTargetRealmName(), filter.uid,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            } else {
                client.realmRole().getRealmRole(schema, configuration.getTargetRealmName(), filter.name,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            }
        }
    }
}
