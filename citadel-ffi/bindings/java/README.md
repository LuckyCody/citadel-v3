# Citadel — Java Binding

Post-quantum hybrid encryption for Java via JNA.
**X25519 + ML-KEM-768 + AES-256-GCM** (NIST FIPS 203/204).

License inquiries: commit@reposignal.io

---

## Requirements

- Java 8 or later
- [JNA 5.x](https://github.com/java-native-access/jna) on classpath
- The native `libcitadel` library for your platform (see below)

---

## Step 1 — Get the native library

Download the prebuilt binary for your platform from the
[citadel-v3 releases page](https://github.com/mrcord77/citadel-v3/releases):

| Platform       | File                    |
|----------------|-------------------------|
| Linux x86_64   | `libcitadel.so`         |
| macOS (ARM/x86)| `libcitadel.dylib`      |
| Windows x86_64 | `citadel.dll`           |

Or build from source:

```bash
git clone https://github.com/mrcord77/citadel-v3
cd citadel-v3
cargo build --release -p citadel-ffi
# Output: target/release/libcitadel.so (or .dll / .dylib)
```

---

## Step 2 — Add JNA to your project

**Maven:**
```xml
<dependency>
  <groupId>net.java.dev.jna</groupId>
  <artifactId>jna</artifactId>
  <version>5.14.0</version>
</dependency>
```

**Gradle:**
```groovy
implementation 'net.java.dev.jna:jna:5.14.0'
```

---

## Step 3 — Add the Java source file

Copy `io/reposignal/citadel/Citadel.java` into your project's source tree.
No additional build steps required — it's a single source file.

---

## Step 4 — Use it

```java
import io.reposignal.citadel.Citadel;
import io.reposignal.citadel.Citadel.KeyPair;

// Optional: specify library path if not on system path
// Citadel.loadLibrary("/path/to/libcitadel.so");

// Generate a keypair
KeyPair kp = Citadel.generateKeyPair();

// Encrypt — bind to a specific record via AAD
byte[] ciphertext = Citadel.seal(
    kp.publicKey,
    patientRecord.getBytes(),
    patientId.getBytes(),        // AAD — ties ciphertext to this patient
    "medical-records".getBytes() // context — domain separation
);

// Decrypt
byte[] plaintext = Citadel.open(
    kp.secretKey,
    ciphertext,
    patientId.getBytes(),
    "medical-records".getBytes()
);
```

---

## Library path

The native library must be findable at runtime. Options:

**Option A — System library path (recommended for production):**
```bash
# Linux
export LD_LIBRARY_PATH=/path/to/lib:$LD_LIBRARY_PATH

# macOS
export DYLD_LIBRARY_PATH=/path/to/lib:$DYLD_LIBRARY_PATH

# Windows — add to PATH or place alongside the .jar
```

**Option B — JVM flag:**
```bash
java -Djna.library.path=/path/to/lib -jar yourapp.jar
```

**Option C — Explicit load in code:**
```java
Citadel.loadLibrary("/absolute/path/to/libcitadel.so");
// Call this before any other Citadel method
```

---

## Key sizes

| Key type   | Size       |
|------------|------------|
| Public key | 1216 bytes |
| Secret key | 2432 bytes |

Both are raw byte arrays. Store public keys alongside the data they protect.
Store secret keys in a secrets manager, HSM, or vault — never in source code.

---

## Error handling

All methods throw `Citadel.CitadelException` (a `RuntimeException`) on failure.
The exception carries an error code:

```java
try {
    byte[] pt = Citadel.open(sk, ct, aad, ctx);
} catch (Citadel.CitadelException e) {
    switch (e.getCode()) {
        case Citadel.CITADEL_ERR_OPEN:
            // Authentication failed — wrong key, wrong AAD, or tampered data
            break;
        case Citadel.CITADEL_ERR_KEY:
            // Key bytes are invalid or corrupt
            break;
        default:
            // Unexpected error
            break;
    }
}
```

---

## Running the tests

```bash
# Compile
javac -cp jna-5.14.0.jar:. \
  io/reposignal/citadel/Citadel.java \
  CitadelTest.java

# Run (set library path to wherever libcitadel is)
java -cp jna-5.14.0.jar:. \
  -Djna.library.path=/path/to/lib \
  CitadelTest
```

Expected output:
```
Citadel Java Binding Tests
==================================================
  PASS  generateKeyPair returns non-null
  PASS  Public key is 1216 bytes
  ...
Results: 24 passed | 0 failed
```

---

## Security properties

- **Post-quantum secure:** ML-KEM-768 (NIST FIPS 203) resists quantum attacks
- **Classical secure:** X25519 provides defense-in-depth
- **Authenticated encryption:** AES-256-GCM — tampering is detected
- **AAD binding:** ciphertext is cryptographically bound to its metadata
- **Context isolation:** data encrypted in one context cannot decrypt in another
- **No plaintext exposure:** plaintext never leaves the process

---

## Commercial licensing

This library is licensed under AGPL-3.0. Commercial use requires a
paid license. Contact **commit@reposignal.io** for pricing.

| Tier       | Revenue threshold      | Annual fee         |
|------------|------------------------|--------------------|
| Startup    | Under $1M/year         | $5,000             |
| Commercial | $1M – $50M/year        | $25,000            |
| Enterprise | Over $50M/year         | $75,000–$150,000   |
