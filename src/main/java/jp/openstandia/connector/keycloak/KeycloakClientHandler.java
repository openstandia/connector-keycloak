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
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.objects.*;

import java.util.Set;

import static jp.openstandia.connector.keycloak.KeycloakUtils.createFullAttributesToGet;

/**
 * Handle keycloak client object.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakClientHandler extends AbstractKeycloakHandler {

    public static final ObjectClass CLIENT_OBJECT_CLASS = new ObjectClass("client");

    private static final Log LOGGER = Log.getLog(KeycloakClientHandler.class);

    // Unique and changeable within the keycloak realm
    public static final String ATTR_CLIENT_ID = "clientId";

    // Unique and unchangeable within the keycloak realm.
    // Don't use "id" here because it conflicts midpoint side.
    public static final String ATTR_CLIENT_UUID = "clientUUID";

    public static final String ATTR_PROTOCOL = "protocol";
    public static final String ATTR_ENABLED = "enabled";
    public static final String ATTR_REDIRECT_URIS = "redirectUris";
    public static final String ATTR_NAME = "name";
    public static final String ATTR_DESCRIPTION = "description";
    public static final String ATTR_ADMIN_URL = "adminUrl";

    // openid-connect
    public static final String ATTR_SECRET = "secret";
    public static final String ATTR_PUBLIC_CLIENT = "publicClient";
    public static final String ATTR_STANDARD_FLOW_ENABLED = "standardFlowEnabled";
    public static final String ATTR_IMPLICIT_FLOW_ENABLED = "implicitFlowEnabled";
    public static final String ATTR_DIRECT_ACCESS_GRANTS_ENABLED = "directAccessGrantsEnabled";
    public static final String ATTR_SERVICE_ACCOUNT_ENABLED = "serviceAccountsEnabled";
    public static final String ATTR_BEARER_ONLY = "bearerOnly";
    public static final String ATTR_BASE_URL = "baseUrl";
    public static final String ATTR_ROOT_URL = "rootUrl";
    public static final String ATTR_ORIGIN = "origin";
    public static final String ATTR_WEB_ORIGINS = "webOrigins";
    public static final String ATTR_AUTHORIZATION_SERVICES_ENABLED = "authorizationServicesEnabled";

    // saml

    public static final String ATTR_ATTRIBUTES = "attributes";

    public KeycloakClientHandler(String instanceName, KeycloakConfiguration configuration, KeycloakClient client,
                                 KeycloakSchema schema) {
        super(instanceName, configuration, client, schema);
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
        return client.client().createClient(schema, configuration.getTargetRealmName(), attributes);
    }

    /**
     * @param uid
     * @param modifications
     * @param options
     * @return
     */
    @Override
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        client.client().updateClient(schema, configuration.getTargetRealmName(), uid, modifications, options);

        return null;
    }

    /**
     * @param uid
     * @param options
     */
    @Override
    public void delete(Uid uid, OperationOptions options) {
        client.client().deleteClient(schema, configuration.getTargetRealmName(), uid, options);
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
        Set<String> attributesToGet = createFullAttributesToGet(schema.clientSchema, options);

        if (filter == null) {
            client.client().getClients(schema, configuration.getTargetRealmName(),
                    resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
        } else {
            if (filter.isByUid()) {
                client.client().getClient(schema, configuration.getTargetRealmName(), filter.uid,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            } else {
                client.client().getClient(schema, configuration.getTargetRealmName(), filter.name,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            }
        }
    }
}
