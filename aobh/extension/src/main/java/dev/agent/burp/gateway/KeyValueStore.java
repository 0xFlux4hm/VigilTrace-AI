package dev.agent.burp.gateway;

import java.util.LinkedHashMap;
import java.util.Map;

/** String key/value persistence seam. Burp mode backs it with {@code persistence().extensionData()}; tests use memory. */
public interface KeyValueStore {
    String get(String key);

    void set(String key, String value);

    void delete(String key);

    /** In-memory implementation (standalone demo, self-test). */
    final class Memory implements KeyValueStore {
        private final Map<String, String> data = new LinkedHashMap<>();

        @Override
        public synchronized String get(String key) {
            return data.get(key);
        }

        @Override
        public synchronized void set(String key, String value) {
            data.put(key, value);
        }

        @Override
        public synchronized void delete(String key) {
            data.remove(key);
        }
    }
}
