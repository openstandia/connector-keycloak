package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;

public interface ObjectClassSchemaCreatorCustomizer extends CustomizerWithPriority<ObjectClassSchemaCreatorCustomizer> {
    ObjectClass getSupportedObjectClass();

    void customize(ObjectClassInfoBuilder builder, String[] attributes);
}
