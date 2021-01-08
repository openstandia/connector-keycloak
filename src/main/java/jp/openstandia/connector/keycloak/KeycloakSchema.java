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

import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.spi.operations.SearchOp;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Schema for Keycloak objects.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakSchema {

    private final KeycloakConfiguration configuration;
    private final KeycloakClient client;

    public String version;
    public int majorVersion;
    public int minorVersion;
    public int patchVersion;

    public final Schema schema;
    public final Map<String, AttributeInfo> userSchema;
    public final Map<String, AttributeInfo> groupSchema;
    public final Map<String, AttributeInfo> clientSchema;

    public KeycloakSchema(KeycloakConfiguration configuration, KeycloakClient client) {
        this.configuration = configuration;
        this.client = client;

        SchemaBuilder schemaBuilder = new SchemaBuilder(KeycloakConnector.class);

        ObjectClassInfo userSchemaInfo = KeycloakUserHandler.getUserSchema(getUserAttributes());
        schemaBuilder.defineObjectClass(userSchemaInfo);

        ObjectClassInfo groupSchemaInfo = KeycloakGroupHandler.getGroupSchema(getGroupAttributes());
        schemaBuilder.defineObjectClass(groupSchemaInfo);

        ObjectClassInfo clientSchemaInfo = KeycloakClientHandler.getClientSchema(getClientAttributes());
        schemaBuilder.defineObjectClass(clientSchemaInfo);

        schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildAttributesToGet(), SearchOp.class);
        schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildReturnDefaultAttributes(), SearchOp.class);

        schema = schemaBuilder.build();

        Map<String, AttributeInfo> userSchemaMap = new HashMap<>();
        for (AttributeInfo info : userSchemaInfo.getAttributeInfo()) {
            userSchemaMap.put(info.getName(), info);
        }

        Map<String, AttributeInfo> groupSchemaMap = new HashMap<>();
        for (AttributeInfo info : groupSchemaInfo.getAttributeInfo()) {
            groupSchemaMap.put(info.getName(), info);
        }

        Map<String, AttributeInfo> clientSchemaMap = new HashMap<>();
        for (AttributeInfo info : clientSchemaInfo.getAttributeInfo()) {
            clientSchemaMap.put(info.getName(), info);
        }

        this.userSchema = Collections.unmodifiableMap(userSchemaMap);
        this.groupSchema = Collections.unmodifiableMap(groupSchemaMap);
        this.clientSchema = Collections.unmodifiableMap(clientSchemaMap);

        this.version = client.getVersion();

        parseVersion();
    }

    private void parseVersion() {
        try {
            String[] s = version.split("\\.");
            this.majorVersion = Integer.parseInt(s[0]);
            this.minorVersion = Integer.parseInt(s[1]);
            if (s[2].contains("-")) {
                String ps = s[2].substring(0, s[2].indexOf("-"));
                this.patchVersion = Integer.parseInt(ps);
            } else {
                this.patchVersion = Integer.parseInt(s[2]);
            }
        } catch (NumberFormatException | IndexOutOfBoundsException e) {
            throw new ConnectorException(String.format("Keycloak returns unexpected version number: %s", version));
        }
    }

    private String[] getUserAttributes() {
        String userAttributes = configuration.getUserAttributes();
        if (userAttributes != null) {
            return userAttributes.split(",");
        }
        return new String[]{};
    }

    private String[] getGroupAttributes() {
        String groupAttributes = configuration.getGroupAttributes();
        if (groupAttributes != null) {
            return groupAttributes.split(",");
        }
        return new String[]{};
    }

    private String[] getClientAttributes() {
        String clientAttributes = configuration.getClientAttributes();
        if (clientAttributes != null) {
            return clientAttributes.split(",");
        }
        return new String[]{};
    }

    public boolean isUserSchema(Attribute attribute) {
        return userSchema.containsKey(attribute.getName());
    }

    public boolean isMultiValuedUserSchema(Attribute attribute) {
        return userSchema.get(attribute.getName()).isMultiValued();
    }

    public boolean isUserSchema(AttributeDelta delta) {
        return userSchema.containsKey(delta.getName());
    }

    public boolean isMultiValuedUserSchema(AttributeDelta delta) {
        return userSchema.get(delta.getName()).isMultiValued();
    }

    public AttributeInfo getUserSchema(String attributeName) {
        return userSchema.get(attributeName);
    }

    public boolean isGroupSchema(Attribute attribute) {
        return groupSchema.containsKey(attribute.getName());
    }

    public boolean isMultiValuedGroupSchema(Attribute attribute) {
        return groupSchema.get(attribute.getName()).isMultiValued();
    }

    public boolean isGroupSchema(AttributeDelta delta) {
        return groupSchema.containsKey(delta.getName());
    }

    public boolean isMultiValuedGroupSchema(AttributeDelta delta) {
        return groupSchema.get(delta.getName()).isMultiValued();
    }

    public AttributeInfo getGroupSchema(String attributeName) {
        return groupSchema.get(attributeName);
    }

    public boolean isClientSchema(Attribute attribute) {
        return clientSchema.containsKey(attribute.getName());
    }

    public boolean isMultiValuedClientSchema(Attribute attribute) {
        return clientSchema.get(attribute.getName()).isMultiValued();
    }

    public boolean isClientSchema(AttributeDelta delta) {
        return clientSchema.containsKey(delta.getName());
    }

    public boolean isMultiValuedClientSchema(AttributeDelta delta) {
        return clientSchema.get(delta.getName()).isMultiValued();
    }

    public AttributeInfo getClientSchema(String attributeName) {
        return clientSchema.get(attributeName);
    }
}
