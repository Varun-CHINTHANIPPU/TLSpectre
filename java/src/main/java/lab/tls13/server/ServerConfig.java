package lab.tls13.server;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/** Validated, deliberately small configuration surface for a local security laboratory. */
public record ServerConfig(
    String provider, String bindHost, int httpsPort, int httpPort, String keyStore,
    List<String> protocols, List<String> cipherSuites, List<String> namedGroups,
    boolean hsts, boolean httpRedirect, boolean sniHostCheck,
    boolean sessionCache, boolean ocspStapling, String ocspResponderUri, int maxPayloadBytes,
    boolean accessLog) {
  private static final Set<String> KEYS = Set.of(
      "provider", "bindHost", "httpsPort", "httpPort", "keyStore", "protocols",
      "cipherSuites", "namedGroups", "hsts", "httpRedirect", "sniHostCheck",
      "sessionCache", "ocspStapling", "ocspResponderUri", "maxPayloadBytes", "jvmFlags",
      "accessLog");

  public static ServerConfig load(Path path) throws Exception {
    Object parsed;
    try (InputStream in = Files.newInputStream(path)) {
      parsed = new Yaml(new SafeConstructor(new LoaderOptions())).load(in);
    }
    if (!(parsed instanceof Map<?, ?> m)) throw new IllegalArgumentException("Expected YAML mapping");
    for (Object key : m.keySet()) if (!KEYS.contains(key)) throw new IllegalArgumentException("Unknown config key: " + key);
    ServerConfig c = new ServerConfig(
        string(m, "provider", "SunJSSE"), string(m, "bindHost", "127.0.0.1"),
        integer(m, "httpsPort", 8443), integer(m, "httpPort", 8080),
        string(m, "keyStore", "pki/out/srv_plain.p12"),
        strings(m, "protocols", List.of("TLSv1.3")),
        strings(m, "cipherSuites", List.of()),
        strings(m, "namedGroups", List.of()),
        bool(m, "hsts", true), bool(m, "httpRedirect", true),
        bool(m, "sniHostCheck", true), bool(m, "sessionCache", false),
        bool(m, "ocspStapling", true), string(m, "ocspResponderUri", "http://127.0.0.1:8888"),
        integer(m, "maxPayloadBytes", 1048576),
        bool(m, "accessLog", false));
    c.validate();
    return c;
  }

  private static String string(Map<?, ?> m, String key, String fallback) {
    Object value = m.get(key);
    if (value == null) return fallback;
    if (!(value instanceof String s)) throw new IllegalArgumentException(key + " must be a string");
    return s;
  }
  private static int integer(Map<?, ?> m, String key, int fallback) {
    Object value = m.get(key);
    if (value == null) return fallback;
    if (!(value instanceof Number n) || n.doubleValue() != n.intValue())
      throw new IllegalArgumentException(key + " must be an integer");
    return n.intValue();
  }
  private static boolean bool(Map<?, ?> m, String key, boolean fallback) {
    Object value = m.get(key);
    if (value == null) return fallback;
    if (!(value instanceof Boolean b)) throw new IllegalArgumentException(key + " must be boolean");
    return b;
  }
  private static List<String> strings(Map<?, ?> m, String key, List<String> fallback) {
    Object value = m.get(key);
    if (value == null) return fallback;
    if (!(value instanceof List<?> list)) throw new IllegalArgumentException(key + " must be an array");
    var result = new ArrayList<String>();
    for (Object item : list) {
      if (!(item instanceof String s) || s.isBlank())
        throw new IllegalArgumentException(key + " entries must be nonempty strings");
      result.add(s);
    }
    return List.copyOf(result);
  }
  private void validate() {
    if (!provider.equals("SunJSSE") && !provider.equals("BCJSSE"))
      throw new IllegalArgumentException("provider must be SunJSSE or BCJSSE");
    if (httpsPort < 1 || httpsPort > 65535 || httpPort < 1 || httpPort > 65535 || httpsPort == httpPort)
      throw new IllegalArgumentException("Invalid ports");
    if (maxPayloadBytes < 1 || maxPayloadBytes > 536870912)
      throw new IllegalArgumentException("maxPayloadBytes must be between 1 and 536870912");
    if (protocols.isEmpty() || protocols.stream().anyMatch(p -> !p.equals("TLSv1.3") && !p.equals("TLSv1.2")))
      throw new IllegalArgumentException("Only TLSv1.3 and TLSv1.2 are supported in this lab");
    if (!ocspResponderUri.startsWith("http://127.0.0.1:") && !ocspResponderUri.startsWith("http://localhost:") && !ocspResponderUri.equals("http://10.77.2.2:8888"))
      throw new IllegalArgumentException("OCSP responder must be loopback for this lab");
    if (keyStore.isBlank()) throw new IllegalArgumentException("Missing keyStore");
  }
}
