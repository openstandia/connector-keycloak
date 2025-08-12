package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.objects.*;

public class GroupObjectClassSchemaCreator extends AbstractObjectClassSchemaCreator {
    private static final ObjectClass OBJECT_CLASS = KeycloakGroupHandler.GROUP_OBJECT_CLASS;

    public GroupObjectClassSchemaCreator(CustomizerRegistry<ObjectClassSchemaCreatorCustomizer> customizerRegistry) {
        super(OBJECT_CLASS, new GroupClassUserSchemaCreatorCustomizer(), customizerRegistry);
    }

    private static class GroupClassUserSchemaCreatorCustomizer extends AbstractObjectClassSchemaCreatorCustomizer {
        public GroupClassUserSchemaCreatorCustomizer() {
            super(OBJECT_CLASS, 0);
        }

        @Override
        public void customize(ObjectClassInfoBuilder builder, String[] attributes) {
            builder.setType(OBJECT_CLASS.getObjectClassValue());

            builder.setType(KeycloakGroupHandler.GROUP_OBJECT_CLASS.getObjectClassValue());

            // __UID__
            builder.addAttributeInfo(AttributeInfoBuilder.define(Uid.NAME)
                    .setRequired(false) // Must be optional. It is not present for create operations
                    .setCreateable(false)
                    .setUpdateable(false)
                    .setNativeName(KeycloakGroupHandler.ATTR_GROUP_ID)
                    .build());

            // __NAME__
            builder.addAttributeInfo(AttributeInfoBuilder.define(Name.NAME)
                    .setRequired(true)
                    .setUpdateable(true)
                    .setNativeName(KeycloakGroupHandler.ATTR_GROUP_NAME)
                    .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                    .build());

            // path(read-only)
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakGroupHandler.ATTR_PATH)
                    .setRequired(false)
                    .setCreateable(false)
                    .setUpdateable(false)
                    .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                    .build());

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

            // Association
            builder.addAttributeInfo(AttributeInfoBuilder.define(KeycloakGroupHandler.ATTR_PARENT_GROUP)
                    .setMultiValued(false)
                    .setReturnedByDefault(false)
                    .build());
        }
    }
}
