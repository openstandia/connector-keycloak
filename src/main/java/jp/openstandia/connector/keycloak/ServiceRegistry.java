package jp.openstandia.connector.keycloak;

import java.util.*;

public class ServiceRegistry<T extends CustomizerWithPriority<T>> {
    private final List<T> services;

    public ServiceRegistry(Class<T> serviceClass) {
        this.services = loadServices(Objects.requireNonNull(serviceClass, "serviceClass cannot be null"));
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

    public List<T> getServices() {
        return Collections.unmodifiableList(services);
    }
}
