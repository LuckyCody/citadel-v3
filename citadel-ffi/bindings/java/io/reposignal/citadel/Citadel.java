// SPDX-License-Identifier: AGPL-3.0-or-later
// citadel-envelope Java binding via JNA
// Package: io.reposignal.citadel
// Requires: jna-5.x.x on the classpath
// License inquiries: commit@reposignal.io

package io.reposignal.citadel;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Citadel — Post-Quantum Hybrid Encryption for Java.
 *
 * <p>Wraps citadel-envelope (X25519 + ML-KEM-768 + AES-256-GCM) via JNA.
 * Loads the native library automatically from the classpath or a user-
 * supplied path.
 *
 * <h2>Quick start</h2>
 * <pre>{@code
 * // Generate a keypair
 * Citadel.KeyPair kp = Citadel.generateKeyPair();
 *
 * // Encrypt
 * byte[] ciphertext = Citadel.seal(
 *     kp.publicKey,
 *     "patient SSN 123-45-6789".getBytes(),
 *     "patient-001".getBytes(),   // AAD — binds ciphertext to this record
 *     "medical-records".getBytes() // context — domain separation
 * );
 *
 * // Decrypt
 * byte[] plaintext = Citadel.open(
 *     kp.secretKey,
 *     ciphertext,
 *     "patient-001".getBytes(),
 *     "medical-records".getBytes()
 * );
 * }</pre>
 *
 * <h2>Dependency (Maven)</h2>
 * <pre>{@code
 * <dependency>
 *   <groupId>net.java.dev.jna</groupId>
 *   <artifactId>jna</artifactId>
 *   <version>5.14.0</version>
 * </dependency>
 * }</pre>
 *
 * <h2>Loading the native library</h2>
 * By default, Citadel looks for {@code libcitadel} on the system library
 * path. To specify a path explicitly:
 * <pre>{@code
 * Citadel.loadLibrary("/path/to/libcitadel.so");
 * }</pre>
 */
public final class Citadel {

    // ── Error codes (mirror citadel-ffi/src/lib.rs) ──────────────────────

    public static final int CITADEL_OK        = 0;
    public static final int CITADEL_ERR_NULL  = 1;
    public static final int CITADEL_ERR_SEAL  = 2;
    public static final int CITADEL_ERR_OPEN  = 3;
    public static final int CITADEL_ERR_KEY   = 4;
    public static final int CITADEL_ERR_ALLOC = 5;

    /** Size of a serialized public key in bytes (1216). */
    public static final int PUBLIC_KEY_BYTES = 1216;

    /** Size of a serialized secret key in bytes (2432). */
    public static final int SECRET_KEY_BYTES = 2432;

    /** Size of a serialized 0xA4 (P-384 + ML-KEM-1024) public key in bytes (1665). */
    public static final int P384_PUBLIC_KEY_BYTES = 1665;

    /** Size of a serialized 0xA4 (P-384 + ML-KEM-1024) secret key in bytes (112). */
    public static final int P384_SECRET_KEY_BYTES = 112;

    // ── JNA interface ─────────────────────────────────────────────────────

    interface NativeLib extends Library {
        int citadel_keygen(
            PointerByReference pkOut, LongByReference pkLen,
            PointerByReference skOut, LongByReference skLen
        );

        int citadel_seal(
            byte[] pkPtr,  long pkLen,
            byte[] ptPtr,  long ptLen,
            byte[] aadPtr, long aadLen,
            byte[] ctxPtr, long ctxLen,
            PointerByReference ctOut, LongByReference ctLenOut
        );

        int citadel_open(
            byte[] skPtr,  long skLen,
            byte[] ctPtr,  long ctLen,
            byte[] aadPtr, long aadLen,
            byte[] ctxPtr, long ctxLen,
            PointerByReference ptOut, LongByReference ptLenOut
        );

        void citadel_free(Pointer ptr, long len);

        String citadel_error_string(int code);

        // 0xA4 (P-384 + ML-KEM-1024) additive symbols; 0xA3 above unchanged.
        int citadel_p384_keygen(
            PointerByReference pkOut, LongByReference pkLen,
            PointerByReference skOut, LongByReference skLen
        );

        int citadel_p384_seal(
            byte[] pkPtr,  long pkLen,
            byte[] ptPtr,  long ptLen,
            byte[] aadPtr, long aadLen,
            byte[] ctxPtr, long ctxLen,
            PointerByReference ctOut, LongByReference ctLenOut
        );

        int citadel_p384_open(
            byte[] skPtr,  long skLen,
            byte[] ctPtr,  long ctLen,
            byte[] aadPtr, long aadLen,
            byte[] ctxPtr, long ctxLen,
            PointerByReference ptOut, LongByReference ptLenOut
        );
    }

    private static volatile NativeLib LIB = null;

    private static NativeLib lib() {
        if (LIB == null) {
            synchronized (Citadel.class) {
                if (LIB == null) {
                    LIB = Native.load("citadel", NativeLib.class);
                }
            }
        }
        return LIB;
    }

    /**
     * Load the native library from an explicit file path.
     * Call this before any other Citadel method if you need to specify
     * a non-default library location.
     *
     * @param path absolute path to libcitadel.so / citadel.dll / libcitadel.dylib
     */
    public static synchronized void loadLibrary(String path) {
        LIB = Native.load(path, NativeLib.class);
    }

    private Citadel() {}

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * A public/secret keypair. Both fields are raw byte arrays.
     * Store the public key alongside the data it protects.
     * Store the secret key securely (HSM, secrets manager, vault).
     */
    public static final class KeyPair {
        /** Serialized public key — 1216 bytes. Share freely. */
        public final byte[] publicKey;
        /** Serialized secret key — 2432 bytes. Keep secret. */
        public final byte[] secretKey;

        KeyPair(byte[] pk, byte[] sk) {
            this.publicKey  = pk;
            this.secretKey  = sk;
        }
    }

    /**
     * Generate a new hybrid post-quantum keypair.
     *
     * <p>Uses X25519 + ML-KEM-768 (FIPS 203). Generates fresh randomness
     * from the OS each call.
     *
     * @return a new {@link KeyPair}
     * @throws CitadelException if key generation fails
     */
    public static KeyPair generateKeyPair() {
        PointerByReference pkRef = new PointerByReference();
        LongByReference     pkLen = new LongByReference();
        PointerByReference skRef = new PointerByReference();
        LongByReference     skLen = new LongByReference();

        int rc = lib().citadel_keygen(pkRef, pkLen, skRef, skLen);
        checkError(rc, "keygen");

        byte[] pk = readAndFree(pkRef, pkLen);
        byte[] sk = readAndFree(skRef, skLen);
        return new KeyPair(pk, sk);
    }

    /**
     * Encrypt plaintext using a recipient's public key.
     *
     * <p>The {@code aad} (Additional Authenticated Data) binds the
     * ciphertext to a specific record — e.g. a patient ID, row ID,
     * or filename. The same {@code aad} must be provided to
     * {@link #open} for decryption to succeed.
     *
     * <p>The {@code context} provides domain separation — e.g.
     * {@code "medical-records"} or {@code "financial-data"}.
     * Data encrypted in one context cannot be decrypted in another.
     *
     * @param publicKey  serialized public key (1216 bytes)
     * @param plaintext  data to encrypt
     * @param aad        additional authenticated data (may be empty)
     * @param context    encryption context (may be empty)
     * @return ciphertext bytes
     * @throws CitadelException on encryption failure
     */
    public static byte[] seal(
        byte[] publicKey,
        byte[] plaintext,
        byte[] aad,
        byte[] context
    ) {
        if (publicKey == null) throw new CitadelException("publicKey is null", CITADEL_ERR_NULL);
        if (plaintext == null) throw new CitadelException("plaintext is null", CITADEL_ERR_NULL);

        byte[] aadSafe = aad     != null ? aad     : new byte[0];
        byte[] ctxSafe = context != null ? context : new byte[0];

        PointerByReference ctRef = new PointerByReference();
        LongByReference     ctLen = new LongByReference();

        int rc = lib().citadel_seal(
            publicKey,  publicKey.length,
            plaintext,  plaintext.length,
            aadSafe,    aadSafe.length,
            ctxSafe,    ctxSafe.length,
            ctRef, ctLen
        );
        checkError(rc, "seal");
        return readAndFree(ctRef, ctLen);
    }

    /**
     * Decrypt a ciphertext using the recipient's secret key.
     *
     * <p>The {@code aad} and {@code context} must exactly match the
     * values used during {@link #seal}. Any mismatch causes decryption
     * to fail — this is the authentication guarantee.
     *
     * @param secretKey  serialized secret key (2432 bytes)
     * @param ciphertext ciphertext from {@link #seal}
     * @param aad        additional authenticated data (must match seal)
     * @param context    encryption context (must match seal)
     * @return plaintext bytes
     * @throws CitadelException if decryption or authentication fails
     */
    public static byte[] open(
        byte[] secretKey,
        byte[] ciphertext,
        byte[] aad,
        byte[] context
    ) {
        if (secretKey  == null) throw new CitadelException("secretKey is null",  CITADEL_ERR_NULL);
        if (ciphertext == null) throw new CitadelException("ciphertext is null", CITADEL_ERR_NULL);

        byte[] aadSafe = aad     != null ? aad     : new byte[0];
        byte[] ctxSafe = context != null ? context : new byte[0];

        PointerByReference ptRef = new PointerByReference();
        LongByReference     ptLen = new LongByReference();

        int rc = lib().citadel_open(
            secretKey,  secretKey.length,
            ciphertext, ciphertext.length,
            aadSafe,    aadSafe.length,
            ctxSafe,    ctxSafe.length,
            ptRef, ptLen
        );
        checkError(rc, "open");
        return readAndFree(ptRef, ptLen);
    }

    // 0xA4 (P-384 + ML-KEM-1024) API — additive; the 0xA3 methods above are unchanged.

    /**
     * Generate a new 0xA4 (P-384 + ML-KEM-1024, CNSA category-5) keypair.
     * Keys are {@link #P384_PUBLIC_KEY_BYTES} / {@link #P384_SECRET_KEY_BYTES} bytes.
     * The name states the algorithms, not "CNSA": implementing the algorithms is not
     * CNSA compliance.
     */
    public static KeyPair generateP384KeyPair() {
        PointerByReference pkRef = new PointerByReference();
        LongByReference    pkLen = new LongByReference();
        PointerByReference skRef = new PointerByReference();
        LongByReference    skLen = new LongByReference();

        int rc = lib().citadel_p384_keygen(pkRef, pkLen, skRef, skLen);
        checkError(rc, "p384 keygen");
        return new KeyPair(readAndFree(pkRef, pkLen), readAndFree(skRef, skLen));
    }

    /** Encrypt to a 0xA4 public key. See {@link #seal} for the aad/context semantics. */
    public static byte[] sealP384(byte[] publicKey, byte[] plaintext, byte[] aad, byte[] context) {
        if (publicKey == null) throw new CitadelException("publicKey is null", CITADEL_ERR_NULL);
        if (plaintext == null) throw new CitadelException("plaintext is null", CITADEL_ERR_NULL);

        byte[] aadSafe = aad     != null ? aad     : new byte[0];
        byte[] ctxSafe = context != null ? context : new byte[0];

        PointerByReference ctRef = new PointerByReference();
        LongByReference    ctLen = new LongByReference();

        int rc = lib().citadel_p384_seal(
            publicKey, publicKey.length,
            plaintext, plaintext.length,
            aadSafe,   aadSafe.length,
            ctxSafe,   ctxSafe.length,
            ctRef, ctLen
        );
        checkError(rc, "p384 seal");
        return readAndFree(ctRef, ctLen);
    }

    /** Decrypt a 0xA4 ciphertext. See {@link #open} for the aad/context semantics. */
    public static byte[] openP384(byte[] secretKey, byte[] ciphertext, byte[] aad, byte[] context) {
        if (secretKey  == null) throw new CitadelException("secretKey is null",  CITADEL_ERR_NULL);
        if (ciphertext == null) throw new CitadelException("ciphertext is null", CITADEL_ERR_NULL);

        byte[] aadSafe = aad     != null ? aad     : new byte[0];
        byte[] ctxSafe = context != null ? context : new byte[0];

        PointerByReference ptRef = new PointerByReference();
        LongByReference    ptLen = new LongByReference();

        int rc = lib().citadel_p384_open(
            secretKey,  secretKey.length,
            ciphertext, ciphertext.length,
            aadSafe,    aadSafe.length,
            ctxSafe,    ctxSafe.length,
            ptRef, ptLen
        );
        checkError(rc, "p384 open");
        return readAndFree(ptRef, ptLen);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static byte[] readAndFree(PointerByReference ref, LongByReference len) {
        Pointer ptr = ref.getValue();
        long    n   = len.getValue();
        byte[]  buf = ptr.getByteArray(0, (int) n);
        lib().citadel_free(ptr, n);
        return buf;
    }

    private static void checkError(int rc, String op) {
        if (rc != CITADEL_OK) {
            String msg = lib().citadel_error_string(rc);
            throw new CitadelException(op + " failed: " + msg, rc);
        }
    }

    // ── Exception ─────────────────────────────────────────────────────────

    /**
     * Thrown when a citadel operation fails.
     */
    public static final class CitadelException extends RuntimeException {
        private final int code;

        CitadelException(String message, int code) {
            super(message);
            this.code = code;
        }

        /** The citadel error code (CITADEL_ERR_*). */
        public int getCode() { return code; }
    }
}
