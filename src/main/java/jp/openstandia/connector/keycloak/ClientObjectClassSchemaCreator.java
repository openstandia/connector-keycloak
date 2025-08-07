package jp.openstandia.connector.keycloak;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;

public class ClientObjectClassSchemaCreator extends AbstractObjectClassSchemaCreator {
    private static final ObjectClass OBJECT_CLASS = KeycloakClientHandler.CLIENT_OBJECT_CLASS;

    public ClientObjectClassSchemaCreator(ServiceRegistry<ObjectClassSchemaCreatorCustomizer> serviceRegistry) {
        super(OBJECT_CLASS, new ClientClassUserSchemaCreatorCustomizer(), serviceRegistry);
    }

    private static class ClientClassUserSchemaCreatorCustomizer extends AbstractObjectClassSchemaCreatorCustomizer {
        public ClientClassUserSchemaCreatorCustomizer() {
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
                    .setNativeName(KeycloakClientHandler.ATTR_CLIENT_UUID)
                    .build());

            // __NAME__
            builder.addAttributeInfo(AttributeInfoBuilder.define(Name.NAME)
                    .setRequired(true)
                    .setUpdateable(true)
                    .setNativeName(KeycloakClientHandler.ATTR_CLIENT_ID)
                    .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                    .build());

            // Common Attributes
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_PROTOCOL)
                    .setRequired(true)
                    .setCreateable(true)
                    .setUpdateable(false)
                    .build());
//        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_ENABLED)
//                .setRequired(true)
//                .setType(Boolean.class)
//                .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_REDIRECT_URIS)
                    .setRequired(false)
                    .setMultiValued(true)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_NAME)
                    .setRequired(false)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_DESCRIPTION)
                    .setRequired(false)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_ADMIN_URL)
                    .setRequired(false)
                    .build());

            // openid-connect
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_SECRET)
                    .setRequired(false)
                    .setType(GuardedString.class)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_PUBLIC_CLIENT)
                    .setRequired(false)
                    .setType(Boolean.class)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_STANDARD_FLOW_ENABLED)
                    .setRequired(false)
                    .setType(Boolean.class)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_IMPLICIT_FLOW_ENABLED)
                    .setRequired(false)
                    .setType(Boolean.class)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_DIRECT_ACCESS_GRANTS_ENABLED)
                    .setRequired(false)
                    .setType(Boolean.class)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_SERVICE_ACCOUNT_ENABLED)
                    .setRequired(false)
                    .setType(Boolean.class)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_BEARER_ONLY)
                    .setRequired(false)
                    .setType(Boolean.class)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_BASE_URL)
                    .setRequired(false)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_ROOT_URL)
                    .setRequired(false)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_ORIGIN)
                    .setRequired(false)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_WEB_ORIGINS)
                    .setRequired(false)
                    .setMultiValued(true)
                    .build());
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_AUTHORIZATION_SERVICES_ENABLED)
                    .setRequired(false)
                    .setType(Boolean.class)
                    .build());

            // __ENABLE__ attribute
            builder.addAttributeInfo(OperationalAttributeInfos.ENABLE);

            // Configured Attributes
            for (String attr : attributes) {
                builder.addAttributeInfo(AttributeInfoBuilder.define(attr)
                        .setRequired(false)
                        .build());
            }

            // Generic Attributes
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakClientHandler.ATTR_ATTRIBUTES)
                    .setRequired(false)
                    .setMultiValued(true)
                    .build());
        }
    }
}
