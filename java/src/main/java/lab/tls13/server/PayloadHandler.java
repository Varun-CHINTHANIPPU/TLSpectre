package lab.tls13.server;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.IteratingCallback;


/** Deterministic bounded-memory response body for handshake and record experiments.
 * Writes are <= 16 KiB; actual TLS records MUST be inspected separately on the wire.
 */
public final class PayloadHandler extends Handler.Abstract {
  private static final int CHUNK_SIZE = 16 * 1024;
  // Pattern period is 256 bytes, so each 16-KiB chunk has the same starting byte.
  private static final byte[] PATTERN = new byte[CHUNK_SIZE];
  static {
    for (int i = 0; i < PATTERN.length; i++)
      PATTERN[i] = (byte) (i * 31 + 17);
  }

  private final int maximum;
  private final boolean accessLog;
  public PayloadHandler(int maximum) { this(maximum, false); }
  public PayloadHandler(int maximum, boolean accessLog) {
    this.maximum = maximum;
    this.accessLog = accessLog;
  }

  @Override public boolean handle(Request request, Response response, Callback callback) {
    String method = request.getMethod();
    if (accessLog) {
      // E1 only: log exactly when the application handler receives a
      // request, rather than at a later asynchronous completion boundary.
      // This includes requests that are subsequently cut off by a TLS alert.
      System.out.println("TLSLAB ACCESS " + method + " " + request.getHttpURI().getPathQuery());
      System.out.flush();
    }
    if (!method.equals("GET") && !method.equals("HEAD")) {
      send(request, response, callback, 405, "Method Not Allowed\n");
      return true;
    }
    String path = request.getHttpURI().getPath();
    if (path.equals("/health")) {
      send(request, response, callback, 200, "ok\n");
      return true;
    }
    if (!path.startsWith("/bytes/")) {
      send(request, response, callback, 404, "Not Found\n");
      return true;
    }
    int size;
    try {
      String number = path.substring("/bytes/".length());
      if (!number.matches("[0-9]{1,10}")) throw new NumberFormatException();
      size = Integer.parseInt(number);
    } catch (NumberFormatException ex) {
      send(request, response, callback, 400, "Bad size\n");
      return true;
    }
    if (size > maximum) {
      send(request, response, callback, 413, "Payload Too Large\n");
      return true;
    }
    response.setStatus(200);
    response.getHeaders().put(HttpHeader.CONTENT_TYPE, "application/octet-stream");
    response.getHeaders().put(HttpHeader.CONTENT_LENGTH, size);
    if (method.equals("HEAD") || size == 0) {
      response.write(true, ByteBuffer.allocate(0), callback);
    } else {
      new StreamPayload(response, callback, size).iterate();
    }
    return true;
  }

  private static void send(Request req, Response res, Callback callback, int status, String text) {
    byte[] data = text.getBytes(StandardCharsets.UTF_8);
    res.setStatus(status);
    res.getHeaders().put(HttpHeader.CONTENT_TYPE, "text/plain; charset=utf-8");
    res.getHeaders().put(HttpHeader.CONTENT_LENGTH, data.length);
    res.write(true, req.getMethod().equals("HEAD") ? ByteBuffer.allocate(0) : ByteBuffer.wrap(data), callback);
  }
  /** Serialized non-blocking chunk writes without allocating the whole body. */
  private static final class StreamPayload extends IteratingCallback {
    private final Response response;
    private final Callback completed;
    private int remaining;

    private StreamPayload(Response response, Callback completed, int bytes) {
      this.response = response;
      this.completed = completed;
      this.remaining = bytes;
    }

    @Override protected Action process() {
      if (remaining == 0) return Action.SUCCEEDED;
      int chunk = Math.min(remaining, CHUNK_SIZE);
      remaining -= chunk;
      response.write(remaining == 0, ByteBuffer.wrap(PATTERN, 0, chunk), this);
      return Action.SCHEDULED;
    }

    @Override protected void onCompleteSuccess() {
      completed.succeeded();
    }

    @Override protected void onCompleteFailure(Throwable cause) {
      completed.failed(cause);
    }
  }

}
