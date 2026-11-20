package lab.tls13.client;

import com.sun.management.OperatingSystemMXBean;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;
import java.lang.management.ManagementFactory;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * E4 bulk HTTPS download measurement, one TLS 1.3 / HTTP 1.1 connection per invocation.
 * Measures wall-time and process CPU only AFTER the configured warm-up byte boundary.
 * This client does not observe server CPU, the actual TLS record lengths, or intrinsics.
 */
public final class BulkClient {
  public static final long DEFAULT_BYTES = 512L * 1024 * 1024;
  public static final long DEFAULT_WARMUP = 64L * 1024 * 1024;
  private static final int BUFFER_SIZE = 16 * 1024;
  private static final int MAX_HEADERS = 16384;
  private static final Set<String> SUITES = Set.of(
      "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256");

  private BulkClient() {}

  public record Headers(int status, Map<String, String> values) {
    public Headers {
      values = Map.copyOf(values);
    }
    public String get(String key) {
      return values.get(key.toLowerCase(Locale.ROOT));
    }
  }

  /**
   * Read headers without a BufferedReader, which can prefetch body data and
   * contaminate the phase boundary. Keep parser deliberately strict.
   */
  public static Headers readHeaders(InputStream input) throws IOException {
    ByteArrayOutputStream collected = new ByteArrayOutputStream(512);
    int matched = 0;
    byte[] boundary = {'\r', '\n', '\r', '\n'};
    while (collected.size() < MAX_HEADERS) {
      int one = input.read();
      if (one < 0) throw new IOException("EOF before HTTP headers");
      collected.write(one);
      matched = one == (boundary[matched] & 255) ? matched + 1 : (one == '\r' ? 1 : 0);
      if (matched == 4) {
        String text = collected.toString(StandardCharsets.ISO_8859_1);
        String[] lines = text.substring(0, text.length() - 4).split("\r\n");
        if (lines.length == 0 || !lines[0].matches("HTTP/1\\.[01] [0-9]{3}( .*)?"))
          throw new IOException("invalid HTTP/1.1 response status");
        int status = Integer.parseInt(lines[0].substring(9, 12));
        Map<String, String> values = new HashMap<>();
        for (int i = 1; i < lines.length; i++) {
          int colon = lines[i].indexOf(':');
          if (colon <= 0) throw new IOException("invalid HTTP header");
          String name = lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT);
          String value = lines[i].substring(colon + 1).trim();
          if (values.putIfAbsent(name, value) != null)
            throw new IOException("duplicate HTTP header: " + name);
        }
        return new Headers(status, values);
      }
    }
    throw new IOException("HTTP header section too large");
  }

  public record Measurement(
      long totalBytes, long warmupBytes, long measuredBytes,
      long handshakeNs, long measuredWallNs, long measuredClientCpuNs,
      String tlsProtocol, String cipherSuite, String provider) {
    public double mibPerSecond() {
      return measuredWallNs > 0
          ? (measuredBytes / 1048576.0) / (measuredWallNs / 1_000_000_000.0)
          : Double.NaN;
    }
    public double clientCpuNsPerByte() {
      return measuredClientCpuNs >= 0 && measuredBytes > 0
          ? ((double) measuredClientCpuNs) / measuredBytes : Double.NaN;
    }
    public String toCsv() {
      return String.format(Locale.ROOT,
          "%s,%s,%s,%d,%d,%d,%d,%d,%d,%.9f,%.9f",
          provider, tlsProtocol, cipherSuite, totalBytes, warmupBytes, measuredBytes,
          handshakeNs, measuredWallNs, measuredClientCpuNs,
          mibPerSecond(), clientCpuNsPerByte());
    }
  }

  private static long processCpuTime() {
    var mx = ManagementFactory.getOperatingSystemMXBean();
    return mx instanceof OperatingSystemMXBean bean ? bean.getProcessCpuTime() : -1;
  }

  /**
   * Download exactly totalBytes from /bytes/{totalBytes}. warmupBytes are
   * read before the two performance clocks are sampled, not timed.
   * A Content-Length mismatch, truncated body, TLS mismatch or early EOF fails.
   */
  public static Measurement run(String host, int port, String sniHost,
                                String provider, String suite, Path trustStore,
                                long totalBytes, long warmupBytes) throws Exception {
    if (port < 1 || port > 65535 || host.isBlank() || sniHost.isBlank())
      throw new IllegalArgumentException("invalid host/port");
    if (!provider.equals("SunJSSE") && !provider.equals("BCJSSE"))
      throw new IllegalArgumentException("unknown JSSE provider");
    if (!SUITES.contains(suite))
      throw new IllegalArgumentException("unsupported TLS 1.3 suite");
    if (totalBytes < 2 || totalBytes > DEFAULT_BYTES || warmupBytes < 0
        || warmupBytes >= totalBytes)
      throw new IllegalArgumentException("invalid payload/warmup size");
    String password = System.getenv("KS_PASS");
    if (password == null || password.isBlank())
      throw new IllegalStateException("KS_PASS is required");
    if (provider.equals("BCJSSE")) {
      BouncyCastleProvider bc = new BouncyCastleProvider();
      Security.addProvider(bc);
      Security.addProvider(new BouncyCastleJsseProvider(bc));
    }
    KeyStore anchors = KeyStore.getInstance("PKCS12");
    try (var stream = new FileInputStream(trustStore.toFile())) {
      anchors.load(stream, password.toCharArray());
    }
    TrustManagerFactory tmf = provider.equals("BCJSSE")
        ? TrustManagerFactory.getInstance("PKIX", "BCJSSE")
        : TrustManagerFactory.getInstance("PKIX");
    tmf.init(anchors);
    SSLContext tls = SSLContext.getInstance("TLSv1.3", provider);
    tls.init(null, tmf.getTrustManagers(), null);
    try (Socket tcp = new Socket()) {
      tcp.connect(new InetSocketAddress(host, port), 10000);
      try (SSLSocket socket = (SSLSocket) tls.getSocketFactory()
          .createSocket(tcp, sniHost, port, true)) {
        SSLParameters settings = socket.getSSLParameters();
        settings.setProtocols(new String[]{"TLSv1.3"});
        settings.setCipherSuites(new String[]{suite});
        settings.setEndpointIdentificationAlgorithm("HTTPS");
        socket.setSSLParameters(settings);
        socket.setSoTimeout(30000);
        long handshakeStart = System.nanoTime();
        socket.startHandshake();
        long handshakeNs = System.nanoTime() - handshakeStart;
        String actualSuite = socket.getSession().getCipherSuite();
        String protocol = socket.getSession().getProtocol();
        if (!suite.equals(actualSuite) || !"TLSv1.3".equals(protocol))
          throw new IOException("TLS negotiation mismatch " + protocol + "/" + actualSuite);

        String request = "GET /bytes/" + totalBytes + " HTTP/1.1\r\n"
            + "Host: " + sniHost + ":" + port + "\r\n"
            + "Accept-Encoding: identity\r\nConnection: close\r\n\r\n";
        socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
        socket.getOutputStream().flush();
        InputStream input = socket.getInputStream();
        Headers response = readHeaders(input);
        if (response.status() != 200) throw new IOException("HTTP status " + response.status());
        if (response.get("transfer-encoding") != null)
          throw new IOException("chunked/transfer-encoded body not valid for E4");
        if (response.get("content-encoding") != null
            && !response.get("content-encoding").equalsIgnoreCase("identity"))
          throw new IOException("unexpected HTTP content encoding");
        if (!Long.toString(totalBytes).equals(response.get("content-length")))
          throw new IOException("unexpected Content-Length: " + response.get("content-length"));

        byte[] buffer = new byte[BUFFER_SIZE];
        readExactly(input, buffer, warmupBytes); // transfer warm-up excluded
        // A two-way phase barrier is enabled ONLY by the E4 harness.
        // Manual CLI runs emit pure CSV without a control marker.
        if ("1".equals(System.getenv("TLSLAB_E4_PHASE_MARKER"))) {
          System.out.println("TLSLAB_E4_WARMUP_COMPLETE");
          System.out.flush();
          if (System.in.read() != 'R') throw new IOException("E4 control ack missing");
        }
        long startCpu = processCpuTime();
        long startNs = System.nanoTime();
        readExactly(input, buffer, totalBytes - warmupBytes);
        long durationNs = System.nanoTime() - startNs;
        long endCpu = processCpuTime();
        long clientCpuNs = startCpu >= 0 && endCpu >= startCpu ? endCpu - startCpu : -1L;
        // No extra body bytes are permitted. This check is outside the timed phase.
        if (input.read() != -1) throw new IOException("unexpected extra body bytes");
        return new Measurement(totalBytes, warmupBytes, totalBytes - warmupBytes,
            handshakeNs, durationNs, clientCpuNs, protocol, actualSuite, provider);
      }
    }
  }

  public static void readExactly(InputStream stream, byte[] scratch, long bytes)
      throws IOException {
    if (bytes < 0 || scratch.length == 0)
      throw new IllegalArgumentException("invalid read limit");
    while (bytes > 0) {
      int ask = (int) Math.min(scratch.length, bytes);
      int count = stream.read(scratch, 0, ask);
      if (count < 0) throw new IOException("truncated HTTP body");
      if (count == 0) continue;
      bytes -= count;
    }
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 8)
      throw new IllegalArgumentException(
        "Usage: BulkClient <connect-host> <port> <sni-host> <SunJSSE|BCJSSE> "
        + "<TLS_AES_128_GCM_SHA256|TLS_AES_256_GCM_SHA384|TLS_CHACHA20_POLY1305_SHA256> "
        + "<total-bytes> <warmup-bytes> <truststore.p12>");
    Measurement result = run(args[0], Integer.parseInt(args[1]), args[2],
        args[3], args[4], Path.of(args[7]), Long.parseLong(args[5]),
        Long.parseLong(args[6]));
    System.out.println("provider,protocol,suite,total_bytes,warmup_bytes,measured_bytes,"
        + "handshake_ns,measured_wall_ns,client_cpu_ns,mib_per_second,client_cpu_ns_per_byte");
    System.out.println(result.toCsv());
  }
}
