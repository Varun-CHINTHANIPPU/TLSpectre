package lab.tls13.client;

import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * Exploratory E5 handshake latency client. Runs a fresh SSLContext for each
 * measurement to discourage PSK reuse; resumption and negotiated key-share
 * group MUST still be verified from independent captures.
 */
public final class HandshakeClient {
  private HandshakeClient() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 7)
      throw new IllegalArgumentException("Usage: HandshakeClient <connect-host> <port> <sni-host> <provider> <named-group> <count> <truststore>");
    String connectHost = args[0], hostname = args[2], provider = args[3], group = args[4];
    int port = Integer.parseInt(args[1]), count = Integer.parseInt(args[5]);
    if (count < 1 || count > 100000) throw new IllegalArgumentException("count out of range");
    String password = System.getenv("KS_PASS");
    if (password == null) throw new IllegalStateException("KS_PASS is required");
    if (provider.equals("BCJSSE")) {
      BouncyCastleProvider bc = new BouncyCastleProvider();
      Security.addProvider(bc);
      Security.addProvider(new BouncyCastleJsseProvider(bc));
    }
    KeyStore trust = KeyStore.getInstance("PKCS12");
    try (FileInputStream input = new FileInputStream(Path.of(args[6]).toFile())) {
      trust.load(input, password.toCharArray());
    }
    TrustManagerFactory trustManagers = provider.equals("BCJSSE")
        ? TrustManagerFactory.getInstance("PKIX", "BCJSSE")
        : TrustManagerFactory.getInstance("PKIX");
    trustManagers.init(trust);
    // Optional untimed client-JVM warm-up against a *different* endpoint
    // (TLSLAB_WARMUP_TARGET=host:port:count). E7 uses it so the first timed
    // handshake is not dominated by class loading/JIT in this fresh JVM, while
    // the measured server's OCSP cache is left untouched. Not printed.
    String warmup = System.getenv("TLSLAB_WARMUP_TARGET");
    if (warmup != null && !warmup.isBlank()) {
      String[] w = warmup.split(":");
      if (w.length != 3) throw new IllegalArgumentException("TLSLAB_WARMUP_TARGET=host:port:count");
      int warmCount = Integer.parseInt(w[2]);
      if (warmCount < 1 || warmCount > 10000) throw new IllegalArgumentException("warm-up count out of range");
      for (int i = 0; i < warmCount; ++i) {
        SSLContext context = SSLContext.getInstance("TLSv1.3", provider);
        context.init(null, trustManagers.getTrustManagers(), null);
        try (Socket tcp = new Socket()) {
          tcp.connect(new InetSocketAddress(w[0], Integer.parseInt(w[1])), 5000);
          try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(tcp, hostname, Integer.parseInt(w[1]), true)) {
            SSLParameters params = socket.getSSLParameters();
            params.setProtocols(new String[] {"TLSv1.3"});
            params.setEndpointIdentificationAlgorithm("HTTPS");
            params.setNamedGroups(new String[] {group});
            socket.setSSLParameters(params);
            socket.setSoTimeout(5000);
            socket.startHandshake();
            socket.getSession().invalidate();
          }
        }
      }
    }
    System.out.println("i,tcp_ns,handshake_ns,provider,requested_group,negotiated_group,protocol,suite,resumption,status");
    for (int i = 0; i < count; ++i) {
      long tcpNs = -1L, handshakeNs = -1L;
      String suite = "", protocol = "", status = "OK";
      try {
        // Deliberately fresh context: different session cache per measurement.
        SSLContext context = SSLContext.getInstance("TLSv1.3", provider);
        context.init(null, trustManagers.getTrustManagers(), null);
        try (Socket tcp = new Socket()) {
          long t0 = System.nanoTime();
          tcp.connect(new InetSocketAddress(connectHost, port), 5000);
          long t1 = System.nanoTime();
          tcpNs = t1 - t0;
          try (SSLSocket socket = (SSLSocket) context.getSocketFactory()
              .createSocket(tcp, hostname, port, true)) {
            SSLParameters params = socket.getSSLParameters();
            params.setProtocols(new String[] {"TLSv1.3"});
            params.setEndpointIdentificationAlgorithm("HTTPS");
            params.setNamedGroups(new String[] {group});
            socket.setSSLParameters(params);
            socket.setSoTimeout(5000);
            long start = System.nanoTime();
            socket.startHandshake();
            handshakeNs = System.nanoTime() - start;
            SSLSession session = socket.getSession();
            protocol = session.getProtocol();
            suite = session.getCipherSuite();
            session.invalidate();
          }
        }
      } catch (Exception ex) {
        status = "FAIL_" + ex.getClass().getSimpleName();
      }
      // JSSE SSLSession does not expose the negotiated TLS named group or PSK flag.
      // UNVERIFIED prevents turning requested config into a fabricated observation.
      System.out.printf("%d,%d,%d,%s,%s,UNVERIFIED,%s,%s,UNVERIFIED,%s%n",
          i, tcpNs, handshakeNs, provider, group, protocol, suite, status);
    }
  }
}
