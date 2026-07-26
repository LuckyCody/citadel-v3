// SPDX-License-Identifier: AGPL-3.0-or-later
// CitadelTest.java — standalone integration test for the Java binding
//
// Compile and run:
//   javac -cp jna-5.14.0.jar:. io/reposignal/citadel/Citadel.java CitadelTest.java
//   java  -cp jna-5.14.0.jar:. -Djna.library.path=/path/to/lib CitadelTest

import io.reposignal.citadel.Citadel;
import io.reposignal.citadel.Citadel.KeyPair;
import io.reposignal.citadel.Citadel.CitadelException;
import java.util.Arrays;

public class CitadelTest {

    static int passed = 0;
    static int failed = 0;

    static void check(String name, boolean condition) {
        if (condition) {
            System.out.println("  PASS  " + name);
            passed++;
        } else {
            System.out.println("  FAIL  " + name);
            failed++;
        }
    }

    public static void main(String[] args) {
        System.out.println("Citadel Java Binding Tests");
        System.out.println("=".repeat(50));

        testKeyGeneration();
        testBasicRoundtrip();
        testWrongKeyFails();
        testWrongAadFails();
        testWrongContextFails();
        testEmptyAadAndContext();
        testKeySizes();
        testP384Suite();
        testUnicodeData();
        testNullHandling();

        System.out.println("\n" + "=".repeat(50));
        System.out.printf("Results: %d passed | %d failed%n", passed, failed);

        if (failed > 0) {
            System.exit(1);
        }
    }

    // ── Tests ──────────────────────────────────────────────────────────

    static void testKeyGeneration() {
        System.out.println("\n── 1. Key Generation ──────────────────────────────");

        KeyPair kp = Citadel.generateKeyPair();
        check("generateKeyPair returns non-null", kp != null);
        check("Public key is 1216 bytes", kp.publicKey.length == Citadel.PUBLIC_KEY_BYTES);
        check("Secret key is 2432 bytes", kp.secretKey.length == Citadel.SECRET_KEY_BYTES);

        // Two keypairs must be different
        KeyPair kp2 = Citadel.generateKeyPair();
        check("Two keypairs are unique (pk)", !Arrays.equals(kp.publicKey, kp2.publicKey));
        check("Two keypairs are unique (sk)", !Arrays.equals(kp.secretKey, kp2.secretKey));
    }

    static void testBasicRoundtrip() {
        System.out.println("\n── 2. Basic Roundtrip ─────────────────────────────");

        KeyPair kp = Citadel.generateKeyPair();
        byte[] plaintext = "patient SSN: 123-45-6789".getBytes();
        byte[] aad       = "patient-001".getBytes();
        byte[] context   = "medical-records".getBytes();

        byte[] ciphertext = Citadel.seal(kp.publicKey, plaintext, aad, context);
        check("seal returns ciphertext", ciphertext != null && ciphertext.length > 0);
        check("ciphertext is longer than plaintext", ciphertext.length > plaintext.length);

        // Plaintext must not appear in ciphertext
        boolean leaked = contains(ciphertext, plaintext);
        check("plaintext not in ciphertext", !leaked);

        byte[] decrypted = Citadel.open(kp.secretKey, ciphertext, aad, context);
        check("open returns plaintext", Arrays.equals(decrypted, plaintext));
    }

    static void testWrongKeyFails() {
        System.out.println("\n── 3. Wrong Key Rejected ──────────────────────────");

        KeyPair kp1 = Citadel.generateKeyPair();
        KeyPair kp2 = Citadel.generateKeyPair();
        byte[] ct = Citadel.seal(
            kp1.publicKey,
            "secret".getBytes(),
            "aad".getBytes(),
            "ctx".getBytes()
        );

        try {
            Citadel.open(kp2.secretKey, ct, "aad".getBytes(), "ctx".getBytes());
            check("Wrong key throws CitadelException", false);
        } catch (CitadelException e) {
            check("Wrong key throws CitadelException", true);
            check("Error code is CITADEL_ERR_OPEN", e.getCode() == Citadel.CITADEL_ERR_OPEN);
        }
    }

    static void testWrongAadFails() {
        System.out.println("\n── 4. Wrong AAD Rejected ──────────────────────────");

        KeyPair kp = Citadel.generateKeyPair();
        byte[] ct = Citadel.seal(
            kp.publicKey,
            "secret".getBytes(),
            "correct-patient".getBytes(),
            "ctx".getBytes()
        );

        try {
            Citadel.open(kp.secretKey, ct, "wrong-patient".getBytes(), "ctx".getBytes());
            check("Wrong AAD throws CitadelException", false);
        } catch (CitadelException e) {
            check("Wrong AAD throws CitadelException", true);
        }
    }

    static void testWrongContextFails() {
        System.out.println("\n── 5. Wrong Context Rejected ──────────────────────");

        KeyPair kp = Citadel.generateKeyPair();
        byte[] ct = Citadel.seal(
            kp.publicKey,
            "secret".getBytes(),
            "aad".getBytes(),
            "medical-records".getBytes()
        );

        try {
            Citadel.open(kp.secretKey, ct, "aad".getBytes(), "financial-data".getBytes());
            check("Wrong context throws CitadelException", false);
        } catch (CitadelException e) {
            check("Wrong context throws CitadelException", true);
        }
    }

    static void testEmptyAadAndContext() {
        System.out.println("\n── 6. Empty AAD and Context ───────────────────────");

        KeyPair kp = Citadel.generateKeyPair();
        byte[] pt = "test data".getBytes();

        // Null AAD/context should work (treated as empty)
        byte[] ct = Citadel.seal(kp.publicKey, pt, null, null);
        check("seal with null aad/ctx succeeds", ct != null);

        byte[] decrypted = Citadel.open(kp.secretKey, ct, null, null);
        check("open with null aad/ctx succeeds", Arrays.equals(decrypted, pt));

        // Empty arrays should also work
        byte[] ct2 = Citadel.seal(kp.publicKey, pt, new byte[0], new byte[0]);
        byte[] dec2 = Citadel.open(kp.secretKey, ct2, new byte[0], new byte[0]);
        check("seal/open with empty aad/ctx", Arrays.equals(dec2, pt));
    }

    static void testKeySizes() {
        System.out.println("\n── 7. Key Size Constants ──────────────────────────");
        check("PUBLIC_KEY_BYTES is 1216", Citadel.PUBLIC_KEY_BYTES == 1216);
        check("SECRET_KEY_BYTES is 2432", Citadel.SECRET_KEY_BYTES == 2432);
    }

    static void testP384Suite() {
        System.out.println("\n-- 7b. 0xA4 (P-384 + ML-KEM-1024) --");
        check("P384_PUBLIC_KEY_BYTES is 1665", Citadel.P384_PUBLIC_KEY_BYTES == 1665);
        check("P384_SECRET_KEY_BYTES is 112", Citadel.P384_SECRET_KEY_BYTES == 112);

        KeyPair kp = Citadel.generateP384KeyPair();
        check("p384 pk is 1665 bytes", kp.publicKey.length == 1665);
        check("p384 sk is 112 bytes", kp.secretKey.length == 112);

        byte[] pt  = "java-p384 (CNSA category-5)".getBytes();
        byte[] aad = "record-042".getBytes();
        byte[] ctx = "emr".getBytes();

        byte[] ct = Citadel.sealP384(kp.publicKey, pt, aad, ctx);
        check("p384 seal returns ciphertext", ct != null && ct.length > pt.length);
        check("p384 plaintext not in ciphertext", !contains(ct, pt));

        byte[] dec = Citadel.openP384(kp.secretKey, ct, aad, ctx);
        check("p384 roundtrip recovers plaintext", Arrays.equals(dec, pt));

        try {
            Citadel.openP384(kp.secretKey, ct, "wrong".getBytes(), ctx);
            check("p384 wrong-AAD throws", false);
        } catch (CitadelException e) {
            check("p384 wrong-AAD throws CitadelException", true);
        }
    }

    static void testUnicodeData() {
        System.out.println("\n── 8. Unicode and Binary Data ─────────────────────");

        KeyPair kp = Citadel.generateKeyPair();
        String msg = "Patient: こんにちは — Diagnosis: Type 2 Diabetes 🏥";
        byte[] pt = msg.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        byte[] ct = Citadel.seal(kp.publicKey, pt, "record-001".getBytes(), "emr".getBytes());
        byte[] dec = Citadel.open(kp.secretKey, ct, "record-001".getBytes(), "emr".getBytes());
        check("Unicode round-trip", Arrays.equals(dec, pt));

        // Binary data
        byte[] binary = new byte[256];
        for (int i = 0; i < 256; i++) binary[i] = (byte) i;
        byte[] bct = Citadel.seal(kp.publicKey, binary, "bin".getBytes(), "test".getBytes());
        byte[] bdec = Citadel.open(kp.secretKey, bct, "bin".getBytes(), "test".getBytes());
        check("Binary data round-trip", Arrays.equals(bdec, binary));
    }

    static void testNullHandling() {
        System.out.println("\n── 9. Null Input Handling ─────────────────────────");

        KeyPair kp = Citadel.generateKeyPair();

        try {
            Citadel.seal(null, "data".getBytes(), null, null);
            check("null publicKey throws", false);
        } catch (CitadelException e) {
            check("null publicKey throws CitadelException", true);
        }

        try {
            Citadel.seal(kp.publicKey, null, null, null);
            check("null plaintext throws", false);
        } catch (CitadelException e) {
            check("null plaintext throws CitadelException", true);
        }

        try {
            Citadel.open(null, new byte[10], null, null);
            check("null secretKey throws", false);
        } catch (CitadelException e) {
            check("null secretKey throws CitadelException", true);
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────

    static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }
}
