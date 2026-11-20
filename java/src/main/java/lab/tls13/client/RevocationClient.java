package lab.tls13.client;

import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.List;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * First E6 revocation-policy measurement client. K2 (hard fail), K3 (soft fail), K4 (default); K6 is extra Must-Staple. No application request
 * is sent until all client-side checks succeed.
 */
public final class RevocationClient {
  private RevocationClient() {}
  private static final String TLS_FEATURE_OID = "1.3.6.1.5.5.7.1.24";

  private static boolean mustStaple(X509Certificate cert) throws Exception {
    byte[] value = cert.getExtensionValue(TLS_FEATURE_OID);
    if (value == null) return false;
    ASN1OctetString outer = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(value));
    ASN1Sequence features = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(outer.getOctets()));
    for (int i = 0; i < features.size(); i++) {
      if (ASN1Integer.getInstance(features.getObjectAt(i)).getValue().intValueExact() == 5)
        return true; // RFC 7633 status_request feature
    }
    return false;
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 6)
      throw new IllegalArgumentException(
          "Usage: RevocationClient <connect-host> <port> <sni-host> <K2|K3|K4|K6> <truststore.p12> <timeout-ms>");
    String host = args[0], hostname = args[2], policy = args[3];
    int port = Integer.parseInt(args[1]), timeout = Integer.parseInt(args[5]);
    if (!List.of("K2", "K3", "K4", "K6").contains(policy))
      throw new IllegalArgumentException("Unknown policy");
    if (timeout < 100 || timeout > 60000) throw new IllegalArgumentException("Invalid timeout");
    String password = System.getenv("KS_PASS");
    if (password == null) throw new IllegalStateException("KS_PASS is required");
    KeyStore anchors = KeyStore.getInstance("PKCS12");
    try (var input = new FileInputStream(Path.of(args[4]).toFile())) {
      anchors.load(input, password.toCharArray());
    }
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
    if (policy.equals("K4")) {
      // The documented default trust-manager path disables revocation checking.
      tmf.init(anchors);
    } else {
      PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, new X509CertSelector());
      params.setRevocationEnabled(true);
      PKIXRevocationChecker checker =
          (PKIXRevocationChecker) CertPathValidator.getInstance("PKIX").getRevocationChecker();
      EnumSet<PKIXRevocationChecker.Option> options =
          EnumSet.of(PKIXRevocationChecker.Option.ONLY_END_ENTITY);
      if (policy.equals("K3")) options.add(PKIXRevocationChecker.Option.SOFT_FAIL);
      checker.setOptions(options);
      params.addCertPathChecker(checker);
      tmf.init(new CertPathTrustManagerParameters(params));
    }
    System.setProperty("jdk.tls.client.enableStatusRequestExtension", "true");
    SSLContext ctx = SSLContext.getInstance("TLSv1.3", "SunJSSE");
    ctx.init(null, tmf.getTrustManagers(), null);
    String result = "REJECT", details = "", staple = "UNKNOWN", feature = "UNKNOWN";
    try (Socket tcp = new Socket()) {
      tcp.connect(new InetSocketAddress(host, port), timeout);
      try (SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(tcp, hostname, port, true)) {
        SSLParameters params = socket.getSSLParameters();
        params.setProtocols(new String[] {"TLSv1.3"});
        params.setEndpointIdentificationAlgorithm("HTTPS");
        socket.setSSLParameters(params);
        socket.setSoTimeout(timeout);
        socket.startHandshake();
        X509Certificate leaf = (X509Certificate) socket.getSession().getPeerCertificates()[0];
        boolean mustStaple = mustStaple(leaf);
        feature = Boolean.toString(mustStaple);
        if (socket.getSession() instanceof ExtendedSSLSession extended) {
          try {
            var responses = extended.getStatusResponses();
            staple = Integer.toString(responses.stream().filter(b -> b != null && b.length > 0).toList().size());
          } catch (UnsupportedOperationException e) {
            staple = "UNSUPPORTED";
          }
        }
        if (policy.equals("K6") && (!mustStaple || !staple.equals("1")))
          throw new IllegalStateException("Required Must-Staple certificate and one stapled OCSP response");
        result = "ACCEPT";
      }
    } catch (Exception ex) {
      // Preserve the causal chain: "SSLHandshakeException" alone hides whether
      // PKIX validation, OCSP retrieval, or TLS stapling caused the failure.
      StringBuilder cause = new StringBuilder();
      for (Throwable current = ex; current != null && cause.length() < 600;
           current = current.getCause()) {
        if (cause.length() > 0) cause.append(" <- ");
        cause.append(current.getClass().getSimpleName());
        if (current.getMessage() != null) {
          cause.append(": ").append(current.getMessage().replaceAll("[\\r\\n]+", " "));
        }
      }
      details = cause.length() > 600 ? cause.substring(0, 600) : cause.toString();
      // A direct socket/connectivity failure is not a certificate-policy result.
      // Do not treat nested OCSP-fetch errors as BLOCKED: hard-fail revocation
      // checks must REJECT when the deliberately unreachable responder is tested.
      if (ex instanceof java.net.ConnectException ||
          ex instanceof java.net.NoRouteToHostException ||
          ex instanceof java.net.SocketTimeoutException ||
          ex instanceof java.net.UnknownHostException)
        result = "BLOCKED";
      else
        result = "REJECT";
    }
    System.out.printf("policy=%s result=%s staple_count=%s must_staple=%s reason=%s%n",
        policy, result, staple, feature, details);
    if (result.equals("REJECT")) System.exit(2);
    if (result.equals("BLOCKED")) System.exit(3);
  }
}
