package jp.openstandia.connector.keycloak.rest;

import jp.openstandia.connector.keycloak.CustomizerWithPriority;
import jp.openstandia.connector.keycloak.KeycloakSchema;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.Uid;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.Set;

public interface KeycloakUserCustomizer extends CustomizerWithPriority<KeycloakUserCustomizer> {
    void customizeUpdateUser(
            KeycloakSchema schema,
            String realmName,
            Uid uid,
            Set<AttributeDelta> modifications,
            OperationOptions options,
            UserRepresentation user,
            Keycloak adminClient
    );

    void customizeToConnectorObject(
            ConnectorObjectBuilder builder,
            String instanceName,
            KeycloakSchema schema,
            String realmName,
            UserRepresentation user,
            Set<String> attributesToGet,
            boolean allowPartialAttributeValues,
            Keycloak adminClient
    );
}
