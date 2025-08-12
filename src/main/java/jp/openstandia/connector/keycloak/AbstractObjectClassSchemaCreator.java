package jp.openstandia.connector.keycloak;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public abstract class AbstractObjectClassSchemaCreator implements ObjectClassSchemaCreator {

    private static final Log LOGGER = Log.getLog(AbstractObjectClassSchemaCreator.class);

    protected final ObjectClass objectClass;
    private final List<ObjectClassSchemaCreatorCustomizer> customizers;

    protected AbstractObjectClassSchemaCreator(
            ObjectClass objectClass,
            ObjectClassSchemaCreatorCustomizer mainCustomizer,
            CustomizerRegistry<ObjectClassSchemaCreatorCustomizer> customizerRegistry
    ) {
        this.objectClass = Objects.requireNonNull(objectClass, "objectClass cannot be null");
        this.customizers = customizersList(
                objectClass,
                Objects.requireNonNull(mainCustomizer, "mainCustomizer cannot be null"),
                Objects.requireNonNull(customizerRegistry, "serviceRegistry cannot be null")
        );
    }

    private static List<ObjectClassSchemaCreatorCustomizer> customizersList(
            ObjectClass objectClass,
            ObjectClassSchemaCreatorCustomizer mainCustomizer,
            CustomizerRegistry<ObjectClassSchemaCreatorCustomizer> customizerRegistry
    ) {
        List<ObjectClassSchemaCreatorCustomizer> result = new ArrayList<>();
        addCustomizers(objectClass, Collections.singletonList(mainCustomizer), result);
        addCustomizers(objectClass, result, customizerRegistry.getCustomizers());

        Collections.sort(result);
        Collections.reverse(result);

        return result;
    }

    private static void addCustomizers(ObjectClass objectClass, List<ObjectClassSchemaCreatorCustomizer> from, List<ObjectClassSchemaCreatorCustomizer> to) {
        for (ObjectClassSchemaCreatorCustomizer customizer : from) {
            if (objectClass.is(customizer.getSupportedObjectClass().getObjectClassValue())) {
                to.add(customizer);
            }
        }
    }

    @Override
    public ObjectClassInfo createSchema(String[] attributes) {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        customizers.forEach((customizer) -> {
            customizer.customize(builder, attributes);
        });
        ObjectClassInfo schema = builder.build();
        LOGGER.info("Schema constructed: {0}", schema);
        return schema;
    }
}
