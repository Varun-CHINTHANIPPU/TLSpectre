package lab.tls13.bench;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.SplittableRandom;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.AuxCounters;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;

/** AEAD primitive benchmark: unique 96-bit nonce per encryption and fixed plaintext sizes. */
@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 5, time = 2)
@Measurement(iterations = 10, time = 2)
@Fork(3)
public class AeadBench {
  @Param({"AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305"})
  public String aead;
  @Param({"SunJCE", "BC"})
  public String provider;
  @Param({"64", "1024", "16384"})
  public int size;

  private Cipher cipher;
  private SecretKeySpec key;
  private byte[] plaintext;
  private byte[] aad;
  private byte[] iv;
  private long counter;

  @Setup(Level.Trial)
  public void init() throws Exception {
    if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
    boolean aes = aead.startsWith("AES");
    int bits = aead.equals("AES-128-GCM") ? 128 : 256;
    byte[] keyBytes = new byte[bits / 8];
    new SplittableRandom(42).nextBytes(keyBytes);
    key = new SecretKeySpec(keyBytes, aes ? "AES" : "ChaCha20");
    cipher = Cipher.getInstance(aes ? "AES/GCM/NoPadding" : "ChaCha20-Poly1305", provider);
    plaintext = new byte[size];
    new SplittableRandom(7).nextBytes(plaintext);
    aad = new byte[5];
    iv = new byte[12];
    counter = 0;
  }

  /**
   * Per-iteration CPU time of the benchmark thread (E3 cpu_ns_per_byte).
   *
   * Sampled with ThreadMXBean once per iteration, never per operation, so the
   * measurement itself does not perturb the timed loop. JMH reports both
   * fields as secondary metrics with one raw value per measurement iteration.
   */
  @State(Scope.Thread)
  @AuxCounters(AuxCounters.Type.EVENTS)
  public static class CpuTime {
    private static final ThreadMXBean MX = ManagementFactory.getThreadMXBean();
    public long cpuNanos;
    public long bytes;
    private long start;

    @Setup(Level.Iteration)
    public void begin() {
      if (!MX.isCurrentThreadCpuTimeSupported()) throw new IllegalStateException("thread CPU time unsupported");
      MX.setThreadCpuTimeEnabled(true);
      cpuNanos = 0;
      bytes = 0;
      start = MX.getCurrentThreadCpuTime();
    }

    @TearDown(Level.Iteration)
    public void end() {
      cpuNanos = MX.getCurrentThreadCpuTime() - start;
    }
  }

  @Benchmark
  public byte[] encrypt(CpuTime cpu) throws Exception {
    cpu.bytes += size;
    // Each benchmark fork starts a fresh key; nonces are never reused within a fork.
    ByteBuffer.wrap(iv, 4, 8).putLong(++counter);
    if (aead.startsWith("AES"))
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
    else
      cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
    cipher.updateAAD(aad);
    return cipher.doFinal(plaintext);
  }
}
