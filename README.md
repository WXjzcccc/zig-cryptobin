# zig-cryptobin

`zig-cryptobin` is a Zig implementation inspired by [`go-cryptobin`](https://github.com/deatil/go-cryptobin). It keeps the same high-level configuration order while making allocation and failures explicit in Zig.

## Supported modules

- Fluent `Cryptobin` API: `From*`, `SetKey`, `SetIv`, algorithm/mode/padding selection, `Encrypt`/`Decrypt`, and `To*` encodings.
- AES-128, AES-192, AES-256 with ECB, CBC, PCBC, CFB, OFB, CTR, GCM, and CCM.
- DES, 2-key TripleDES, and 3-key TripleDES with ECB, CBC, PCBC, CFB, OFB, and CTR.
- RC4 and RC4-MD5 stream ciphers.
- TEA (including configurable even round counts) and XTEA.
- SM4 with ECB, CBC, PCBC, CFB, OFB, and CTR.
- ChaCha20, ChaCha20-Poly1305, and XChaCha20-Poly1305.
- NoPadding, Zero, PKCS5, PKCS7, X9.23, ISO10126, ISO7816-4, ISO97971, PBOC2, and TBC padding.
- Base64 and hexadecimal codecs.
- Canonical bencode values (integer, bytes, list, and dictionary).
- MD5, SHA-1, SHA-2, SHA-3, SM3, HMAC (MD5/SHA-1/SHA-2/SM3), PBKDF2 (SHA-256/SHA-512), HKDF-SHA-256, scrypt, bcrypt-PBKDF, and OpenSSH bcrypt KDF.
- AES-CMAC for AES-128 and AES-256.
- Cryptographically secure random bytes and SSH-style random-art fingerprints.
- OpenPGP S2K derivation with MD5, SHA-1, SHA-256, and SHA-512.
- X25519 key generation, public-key derivation, and ECDH shared-secret calculation.
- Ed25519 key generation, deterministic signing, and signature verification.

## Usage

### Add as a dependency

From another Zig 0.16 project, add this repository as a dependency. While working from a local checkout:

```sh
zig fetch --save path-to-zig-cryptobin
```

To use this repository from GitHub, replace `<commit-or-tag>` with a released tag or an immutable commit SHA:

```sh
zig fetch --save https://github.com/WXjzcccc/zig-cryptobin/archive/<commit-or-tag>.tar.gz
```

This adds a `zig_cryptobin` entry to the consuming project's `build.zig.zon`. In its `build.zig`, expose the package module to the application root module:

```zig
const cryptobin_dependency = b.dependency("zig_cryptobin", .{
    .target = target,
    .optimize = optimize,
});
const cryptobin_module = cryptobin_dependency.module("zig_cryptobin");

executable.root_module.addImport("zig_cryptobin", cryptobin_module);
```

For a test artifact or library root module, call `addImport` on that root module instead of `executable.root_module`. Application code can then import it as shown below.

```zig
const std = @import("std");
const cryptobin = @import("zig_cryptobin");

var value = try cryptobin.FromString(std.heap.page_allocator, "useData");
defer value.deinit();

_ = try value.SetKey("dfertf12dfertf12");
_ = try value.SetIv("1234567890abcdef");
_ = try value.Aes().CBC().PKCS7Padding().Encrypt();

const encoded = try value.ToBase64String();
defer std.heap.page_allocator.free(encoded);
```

X25519 uses fixed-size key values and verifies invalid points during ECDH:

```zig
const x25519 = cryptobin.x25519;

const alice = x25519.generateKey();
const bob = x25519.generateKey();
const alice_shared = try x25519.ecdh(alice.secret_key, bob.public_key);
const bob_shared = try x25519.ecdh(bob.secret_key, alice.public_key);
std.debug.assert(std.mem.eql(u8, &alice_shared, &bob_shared));
```

```zig
const ed25519 = cryptobin.ed25519;

const signer = ed25519.generateKey();
const signature = try ed25519.sign(signer.secret_key, "message");
std.debug.assert(ed25519.verify(signer.public_key, "message", signature));
```

`Cryptobin` defaults to AES, ECB, and NoPadding, matching `go-cryptobin`. Each `Cryptobin` instance owns its copied input, key, IV, associated data, and output; call `deinit()` once it is no longer needed.

## Verification

Run all unit and interoperability-vector tests with:

```sh
zig build test
```

The current test suite includes FIPS-197 AES-192, RFC 8439 ChaCha20, AES-GCM, ChaCha20-Poly1305, padding, codecs, hash, KDF, and fluent encrypt/decrypt round trips.

## Compatibility status

The original `go-cryptobin` includes a much broader catalogue of historical ciphers, asymmetric cryptography, PKCS containers, SSH, and X.509. Apart from X25519 and Ed25519, those asymmetric and container modules are not yet implemented in this Zig package; unsupported algorithms are intentionally not exposed as successful operations.
