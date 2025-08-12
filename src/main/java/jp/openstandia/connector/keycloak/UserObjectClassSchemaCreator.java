package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.objects.*;

import java.time.ZonedDateTime;

import static jp.openstandia.connector.keycloak.KeycloakUserHandler.USER_OBJECT_CLASS;

public class UserObjectClassSchemaCreator extends AbstractObjectClassSchemaCreator {
    private static final ObjectClass OBJECT_CLASS = USER_OBJECT_CLASS;

    public UserObjectClassSchemaCreator(CustomizerRegistry<ObjectClassSchemaCreatorCustomizer> customizerRegistry) {
        super(OBJECT_CLASS, new ObjectClassUserSchemaCreatorCustomizer(), customizerRegistry);
    }

    private static class ObjectClassUserSchemaCreatorCustomizer extends AbstractObjectClassSchemaCreatorCustomizer {
        public ObjectClassUserSchemaCreatorCustomizer() {
            super(OBJECT_CLASS, 0);
        }

        @Override
        public void customize(ObjectClassInfoBuilder builder, String[] attributes) {
            builder.setType(OBJECT_CLASS.getObjectClassValue());

            // sub (__UID__)
            builder.addAttributeInfo(
                    AttributeInfoBuilder.define(Uid.NAME)
                            .setRequired(false) // Must be optional. It is not present for create operations
                            .setCreateable(false)
                            .setUpdateable(false)
                            .setNativeName(KeycloakUserHandler.ATTR_USER_ID)
                            .build()
            );

            // username (__NAME__)
            builder.addAttributeInfo(
                    AttributeInfoBuilder.define(Name.NAME)
                            .setRequired(true)
                            .setUpdateable(true)
                            .setNativeName(KeycloakUserHandler.ATTR_USERNAME)
                            .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                            .build()
            );

            // __ENABLE__ attribute
            builder.addAttributeInfo(OperationalAttributeInfos.ENABLE);

            // __PASSWORD__ attribute
            builder.addAttributeInfo(OperationalAttributeInfos.PASSWORD);
//        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_PASSWORD_PERMANENT)
//                .setType(Boolean.class)
//                .setReadable(false)
//                .setReturnedByDefault(false)
//                .build());

            // email
            builder.addAttributeInfo(
                    AttributeInfoBuilder.define(KeycloakUserHandler.ATTR_EMAIL)
                            .setRequired(false)
                            .setUpdateable(true)
                            .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                            .build()
            );
            builder.addAttributeInfo(
                    AttributeInfoBuilder.define(KeycloakUserHandler.ATTR_EMAIL_VERIFIED)
                            .setType(Boolean.class)
                            .setRequired(false)
                            .setUpdateable(true)
                            .build()
            );

            // firstName
            builder.addAttributeInfo(
                    AttributeInfoBuilder.define(KeycloakUserHandler.ATTR_FIRST_NAME)
                            .setRequired(false)
                            .setUpdateable(true)
                            .build()
            );

            // lastName
            builder.addAttributeInfo(
                    AttributeInfoBuilder.define(KeycloakUserHandler.ATTR_LAST_NAME)
                            .setRequired(false)
                            .setUpdateable(true)
                            .build()
            );

            // Attributes
            for (String attr : attributes) {
                String attrName;
                boolean multivalued = false;

                if (attr.contains(":")) {
                    String[] metadata = attr.split(":");
                    attrName = metadata[0];
                    multivalued = metadata[1].equalsIgnoreCase("multivalued");
                } else {
                    attrName = attr;
                }
                builder.addAttributeInfo(
                        AttributeInfoBuilder.define(attrName)
                                .setRequired(false)
                                .setUpdateable(true)
                                .setMultiValued(multivalued)
                                .build()
                );
            }

            // Metadata
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakUserHandler.ATTR_CREATED_TIMESTAMP)
                    .setType(ZonedDateTime.class)
                    .setCreateable(false)
                    .setUpdateable(false)
                    .build());

            // Association
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakUserHandler.ATTR_GROUPS)
                    .setMultiValued(true)
                    .setReturnedByDefault(false)
                    .build());
        }
    }
}
