package jp.openstandia.connector.keycloak;

public interface CustomizerWithPriority<T> extends Comparable<T> {
    int getPriority();

    @Override
    default int compareTo(T o) {
        if (o instanceof CustomizerWithPriority) {
            return Integer.compare(((CustomizerWithPriority<?>) o).getPriority(), this.getPriority());
        } else {
            throw new IllegalArgumentException("compareTo with non " + this.getClass().getSimpleName() + ", but with " + o.getClass());
        }
    }

}
