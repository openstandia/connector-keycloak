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

import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;

/**
 * Utilities for Keycloak Admin REST client.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakRESTUtils {

    public static String getGeneratedId(Response result) {
        String[] path = result.getLocation().getPath().split("/");
        String id = path[path.length - 1];
        return id;
    }

    public static String checkCreateResult(Response result, String apiName) {
        if (result.getStatus() == Response.Status.CREATED.getStatusCode()) {
            return getGeneratedId(result);
        }

        if (result.getStatus() == Response.Status.CONFLICT.getStatusCode()) {
            throw new AlreadyExistsException(String.format("Already exists when calling \"%s\". status. %d",
                    apiName, result.getStatus()));
        }

        throw new ConnectorException(String.format("Keycloak returns unexpected error when calling \"%s\". status: %d",
                apiName, result.getStatus()));
    }

    public static void checkDeleteResult(Response result, String apiName) {
        if (result.getStatus() == Response.Status.NO_CONTENT.getStatusCode()) {
            return;
        }

        if (result.getStatus() == Response.Status.NOT_FOUND.getStatusCode()) {
            throw new NotFoundException(String.format("Not found error when calling \"%s\". status: %d",
                    apiName, result.getStatus()));
        }

        throw new ConnectorException(String.format("Keycloak returns unexpected error when calling \"%s\". status: %d",
                apiName, result.getStatus()));
    }
}
