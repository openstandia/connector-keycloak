package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.objects.*;

import static jp.openstandia.connector.keycloak.KeycloakClientRoleHandler.*;

public class ClientRoleObjectClassSchemaCreator extends AbstractObjectClassSchemaCreator {
    private static final ObjectClass OBJECT_CLASS = CLIENT_ROLE_OBJECT_CLASS;

    public ClientRoleObjectClassSchemaCreator(ServiceRegistry<ObjectClassSchemaCreatorCustomizer> serviceRegistry) {
        super(OBJECT_CLASS, new ObjectClassClientRoleSchemaCreatorCustomizer(), serviceRegistry);
    }

    private static class ObjectClassClientRoleSchemaCreatorCustomizer extends AbstractObjectClassSchemaCreatorCustomizer {
        public ObjectClassClientRoleSchemaCreatorCustomizer() {
            super(OBJECT_CLASS, 0);
        }

        @Override
        public void customize(ObjectClassInfoBuilder builder, String[] attributes) {
            builder.setType(OBJECT_CLASS.getObjectClassValue());

            // __UID__
            builder.addAttributeInfo(AttributeInfoBuilder.define(Uid.NAME)
                    .setRequired(false) // Must be optional. It is not present for create operations
                    .setCreateable(false)
                    .setUpdateable(false)
                    .setNativeName(ATTR_CLIENT_ROLE_ID)
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
        }
    }
}
