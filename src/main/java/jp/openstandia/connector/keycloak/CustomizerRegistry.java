package jp.openstandia.connector.keycloak;

import java.util.*;

public class CustomizerRegistry<T extends CustomizerWithPriority<T>> {
    private final List<T> customizers;

    public CustomizerRegistry(Class<T> serviceClass) {
        this.customizers = loadServices(Objects.requireNonNull(serviceClass, "serviceClass cannot be null"));
    }

    private List<T> loadServices(Class<T> serviceClass) {
        List<T> loaded = new ArrayList<>();
        for (T customizer : ServiceLoader.load(serviceClass)) {
            loaded.add(customizer);
        }

        Collections.sort(loaded);
        Collections.reverse(loaded);

        return loaded;
    }

    public List<T> getCustomizers() {
        return Collections.unmodifiableList(customizers);
    }
}
