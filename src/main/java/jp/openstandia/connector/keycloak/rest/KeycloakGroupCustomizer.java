package jp.openstandia.connector.keycloak.rest;

import jp.openstandia.connector.keycloak.CustomizerWithPriority;
import jp.openstandia.connector.keycloak.KeycloakSchema;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.Uid;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.GroupRepresentation;

import java.util.Set;

public interface KeycloakGroupCustomizer extends CustomizerWithPriority<KeycloakGroupCustomizer> {
    void customizeUpdateGroup(
            KeycloakSchema schema,
            String realmName,
            Uid uid,
            Set<AttributeDelta> modifications,
            OperationOptions options,
            GroupRepresentation group,
            Keycloak adminClient
    );

    void customizeToConnectorObject(
            ConnectorObjectBuilder builder,
            String instanceName,
            KeycloakSchema schema,
            String realmName,
            GroupRepresentation group,
            Set<String> attributesToGet,
            boolean allowPartialAttributeValues,
            Keycloak adminClient
    );
}
