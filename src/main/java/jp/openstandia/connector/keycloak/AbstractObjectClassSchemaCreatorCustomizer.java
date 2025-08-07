package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.objects.ObjectClass;

import java.util.Objects;

public abstract class AbstractObjectClassSchemaCreatorCustomizer implements ObjectClassSchemaCreatorCustomizer {
    private final ObjectClass supportedObjectClass;
    private final int priority;

    public AbstractObjectClassSchemaCreatorCustomizer(ObjectClass supportedObjectClass, int priority) {
        this.supportedObjectClass = Objects.requireNonNull(supportedObjectClass, "supportedObjectClass is mandatory");
        this.priority = priority;
    }

    @Override
    public ObjectClass getSupportedObjectClass() {
        return supportedObjectClass;
    }

    @Override
    public int getPriority() {
        return priority;
    }
}
