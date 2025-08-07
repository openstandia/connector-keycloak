package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.objects.ObjectClassInfo;

public interface ObjectClassSchemaCreator {
    ObjectClassInfo createSchema(String[] attributes);
}
