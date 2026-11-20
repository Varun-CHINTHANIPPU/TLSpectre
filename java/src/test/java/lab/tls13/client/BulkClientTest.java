package lab.tls13.client;

import static org.junit.jupiter.api.Assertions.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class BulkClientTest {
  private static ByteArrayInputStream input(String value) {
    return new ByteArrayInputStream(value.getBytes(StandardCharsets.US_ASCII));
  }

  @Test void parsesHeadersWithoutConsumingBody() throws Exception {
    var stream = input("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nX-Test: yes\r\n\r\nbody");
    var headers = BulkClient.readHeaders(stream);
    assertEquals(200, headers.status());
    assertEquals("10", headers.get("content-length"));
    assertEquals("yes", headers.get("x-test"));
    assertEquals('b', stream.read()); // no accidental body prefetch
  }

  @Test void rejectsDuplicateContentLength() {
    assertThrows(IOException.class, () -> BulkClient.readHeaders(input(
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nCONTENT-LENGTH: 12\r\n\r\n")));
  }

  @Test void rejectsMalformedOrTruncatedHeaders() {
    assertThrows(IOException.class, () -> BulkClient.readHeaders(input("HTTP/1.1 200 OK\n\n")));
    assertThrows(IOException.class, () -> BulkClient.readHeaders(input("garbage\r\n\r\n")));
  }

  @Test void readsWarmupWithoutOvershootingBoundary() throws Exception {
    var stream = input("123456789abcdef");
    byte[] scratch = new byte[8];
    BulkClient.readExactly(stream, scratch, 5);
    assertEquals('6', stream.read());
    BulkClient.readExactly(stream, scratch, 6);
    assertEquals('d', stream.read());
  }

  @Test void failsOnTruncatedBody() {
    assertThrows(IOException.class, () -> BulkClient.readExactly(input("123"), new byte[2], 4));
  }

  @Test void computesGoodputAndCpuCostUsingMeasuredPhaseOnly() {
    long measured = 448L * 1024 * 1024;
    var result = new BulkClient.Measurement(
        512L * 1024 * 1024, 64L * 1024 * 1024, measured,
        123456, 1_000_000_000L, measured * 2,
        "TLSv1.3", "TLS_AES_128_GCM_SHA256", "SunJSSE");
    assertEquals(448.0, result.mibPerSecond(), 1e-10);
    assertEquals(2.0, result.clientCpuNsPerByte(), 1e-10);
    assertTrue(result.toCsv().contains("TLS_AES_128_GCM_SHA256"));
  }
}
