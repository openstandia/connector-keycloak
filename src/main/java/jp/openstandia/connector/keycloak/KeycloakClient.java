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

import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;

import java.util.Set;

/**
 * KeycloakClient interface.
 *
 * @author Hiroyuki Wada
 */
public interface KeycloakClient {
    void test(String realmName);

    String getVersion();

    User user();

    Group group();

    interface User {
        Uid createUser(KeycloakSchema schema, String realmName, Set<Attribute> createAttributes) throws AlreadyExistsException;

        Set<AttributeDelta> updateUser(KeycloakSchema schema, String realmName, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException;

        void deleteUser(KeycloakSchema schema, String realmName, Uid uid, OperationOptions options) throws UnknownUidException;

        void getUsers(KeycloakSchema schema, String realmName, ResultsHandler handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize);

        void getUser(KeycloakSchema schema, String realmName, Uid uid, ResultsHandler handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize);

        void getUser(KeycloakSchema schema, String realmName, Name name, ResultsHandler handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize);
    }

    interface Group {
        Uid createGroup(KeycloakSchema schema, String realmName, Set<Attribute> createAttributes) throws AlreadyExistsException;

        Set<AttributeDelta> updateGroup(KeycloakSchema schema, String realmName, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException;

        void deleteGroup(KeycloakSchema schema, String realmName, Uid uid, OperationOptions options) throws UnknownUidException;

        void getGroups(KeycloakSchema schema, String realmName, ResultsHandler handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize);

        void getGroup(KeycloakSchema schema, String realmName, Uid uid, ResultsHandler handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize);

        void getGroup(KeycloakSchema schema, String realmName, Name name, ResultsHandler handler, OperationOptions options, Set<String> attributesToGet, int queryPageSize);
    }

    void close();
}

