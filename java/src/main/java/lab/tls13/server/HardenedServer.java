package lab.tls13.server;

import java.nio.file.Path;
import java.security.Security;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.SecuredRedirectHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;

public final class HardenedServer {
  private HardenedServer() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 1) throw new IllegalArgumentException("Usage: tlslab-server <config.yaml>");
    ServerConfig c = ServerConfig.load(Path.of(args[0]));
    // Set JSSE stapling parameters before the SSLContext/provider is initialized.
    System.setProperty("jdk.tls.server.enableStatusRequestExtension", Boolean.toString(c.ocspStapling()));
    if (c.ocspStapling()) {
      System.setProperty("jdk.tls.stapling.responderURI", c.ocspResponderUri());
      System.setProperty("jdk.tls.stapling.responderOverride", "true");
      System.setProperty("jdk.tls.stapling.responseTimeout", "5000");
    }
    String password = System.getenv("KS_PASS");
    if (password == null || password.isEmpty()) throw new IllegalStateException("Set KS_PASS in the environment");
    if (c.provider().equals("SunJSSE") && c.namedGroups().stream().anyMatch(g -> g.contains("MLKEM"))
        && Runtime.version().feature() < 27)
      throw new IllegalStateException("SunJSSE ML-KEM hybrid groups require JDK 27+");
    if (c.provider().equals("BCJSSE")) {
      BouncyCastleProvider bc = new BouncyCastleProvider();
      Security.addProvider(bc);
      Security.addProvider(new BouncyCastleJsseProvider(bc));
    }
    Server server = new Server();
    SslContextFactory.Server ssl = new SslContextFactory.Server() {
      @Override public void customize(SSLEngine engine) {
        super.customize(engine);
        // BCJSSE's named-group support must be established by a handshake capture;
        // never assume the JDK SSLParameters implementation controls that provider.
        if (c.provider().equals("SunJSSE") && !c.namedGroups().isEmpty()) {
          SSLParameters params = engine.getSSLParameters();
          params.setNamedGroups(c.namedGroups().toArray(String[]::new));
          engine.setSSLParameters(params);
        }
      }
    };
    ssl.setProvider(c.provider());
    if (c.provider().equals("BCJSSE")) {
      // Use BCJSSE's own PKIX key manager rather than the JVM's default
      // SunX509 key manager. TLS 1.3 requires a usable certificate signer
      // even though cipher suites no longer encode the signing algorithm.
      ssl.setKeyManagerFactoryAlgorithm("PKIX");
      ssl.setTrustManagerFactoryAlgorithm("PKIX");
    }
    ssl.setKeyStoreType("PKCS12");
    ssl.setKeyStorePath(c.keyStore());
    ssl.setKeyStorePassword(password);
    ssl.setIncludeProtocols(c.protocols().toArray(String[]::new));
    if (!c.cipherSuites().isEmpty())
      ssl.setIncludeCipherSuites(c.cipherSuites().toArray(String[]::new));
    ssl.setUseCipherSuitesOrder(true);
    ssl.setRenegotiationAllowed(false);
    ssl.setSessionCachingEnabled(c.sessionCache());

    HttpConfiguration https = new HttpConfiguration();
    https.setSendServerVersion(false);
    https.setSendXPoweredBy(false);
    SecureRequestCustomizer secure = new SecureRequestCustomizer();
    secure.setSniHostCheck(c.sniHostCheck());
    // Jetty checks SNI against the presented certificate only when required.
    // Host-header verification alone does not reject SNI=other.test, Host=lab.test.
    secure.setSniRequired(c.sniHostCheck());
    secure.setStsMaxAge(c.hsts() ? 63072000L : -1L);
    secure.setStsIncludeSubDomains(c.hsts());
    https.addCustomizer(secure);
    ServerConnector tls = new ServerConnector(server,
        new SslConnectionFactory(ssl, HttpVersion.HTTP_1_1.asString()),
        new HttpConnectionFactory(https));
    tls.setHost(c.bindHost());
    tls.setPort(c.httpsPort());

    HttpConfiguration http = new HttpConfiguration();
    http.setSendServerVersion(false);
    http.setSendXPoweredBy(false);
    http.setSecureScheme("https");
    http.setSecurePort(c.httpsPort());
    ServerConnector plain = new ServerConnector(server, new HttpConnectionFactory(http));
    plain.setHost(c.bindHost());
    plain.setPort(c.httpPort());
    server.setConnectors(new Connector[] {tls, plain});

    org.eclipse.jetty.server.Handler app = new PayloadHandler(c.maxPayloadBytes(), c.accessLog());
    if (c.httpRedirect()) app = new SecuredRedirectHandler(app, 308);
    server.setHandler(app);
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      try { server.stop(); } catch (Exception ex) { ex.printStackTrace(); }
    }));
    server.start();
    System.out.printf("TLSLAB READY provider=%s bind=%s https=%d http=%d%n",
        c.provider(), c.bindHost(), c.httpsPort(), c.httpPort());
    server.join();
  }
}
