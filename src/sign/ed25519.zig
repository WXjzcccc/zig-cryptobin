const std = @import("std");

const StdEd25519 = std.crypto.sign.Ed25519;

pub const seed_length = StdEd25519.KeyPair.seed_length;
pub const public_key_length = StdEd25519.PublicKey.encoded_length;
pub const secret_key_length = StdEd25519.SecretKey.encoded_length;
pub const signature_length = StdEd25519.Signature.encoded_length;

pub const Seed = [seed_length]u8;
pub const PublicKey = [public_key_length]u8;
pub const SecretKey = [secret_key_length]u8;
pub const Signature = [signature_length]u8;

pub const Error = error{
    InvalidSeedLength,
    InvalidPublicKeyLength,
    InvalidSecretKeyLength,
    InvalidSignatureLength,
} || std.crypto.errors.IdentityElementError || std.crypto.errors.NonCanonicalError || std.crypto.errors.EncodingError || std.crypto.errors.KeyMismatchError || std.crypto.errors.WeakPublicKeyError;

pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    /// Derives a deterministic Ed25519 key pair from seed.
    /// Ownership: the returned fixed-size key pair is an inline value and requires no release.
    pub fn fromSeed(seed: Seed) Error!KeyPair {
        const key_pair = try StdEd25519.KeyPair.generateDeterministic(seed);
        return .{
            .public_key = key_pair.public_key.toBytes(),
            .secret_key = key_pair.secret_key.toBytes(),
        };
    }

    /// Reconstructs an Ed25519 key pair from its encoded secret key.
    /// Ownership: the returned fixed-size key pair is an inline value and requires no release.
    pub fn fromSecretKey(secret_key: SecretKey) Error!KeyPair {
        const raw_secret_key = try StdEd25519.SecretKey.fromBytes(secret_key);
        const key_pair = try StdEd25519.KeyPair.fromSecretKey(raw_secret_key);
        return .{
            .public_key = key_pair.public_key.toBytes(),
            .secret_key = key_pair.secret_key.toBytes(),
        };
    }
};

/// Converts a byte slice to a fixed-size Ed25519 seed.
/// Ownership: the returned seed is an inline array and requires no release.
pub fn seedFromBytes(bytes: []const u8) Error!Seed {
    if (bytes.len != seed_length) return error.InvalidSeedLength;
    return bytes[0..seed_length].*;
}

/// Converts a byte slice to a fixed-size Ed25519 public key.
/// Ownership: the returned key is an inline array and requires no release.
pub fn publicKeyFromBytes(bytes: []const u8) Error!PublicKey {
    if (bytes.len != public_key_length) return error.InvalidPublicKeyLength;
    return bytes[0..public_key_length].*;
}

/// Converts a byte slice to a fixed-size Ed25519 secret key.
/// Ownership: the returned key is an inline array and requires no release.
pub fn secretKeyFromBytes(bytes: []const u8) Error!SecretKey {
    if (bytes.len != secret_key_length) return error.InvalidSecretKeyLength;
    return bytes[0..secret_key_length].*;
}

/// Converts a byte slice to a fixed-size Ed25519 signature.
/// Ownership: the returned signature is an inline array and requires no release.
pub fn signatureFromBytes(bytes: []const u8) Error!Signature {
    if (bytes.len != signature_length) return error.InvalidSignatureLength;
    return bytes[0..signature_length].*;
}

/// Generates a random Ed25519 key pair.
/// Ownership: the returned fixed-size key pair is an inline value and requires no release.
pub fn generateKey() KeyPair {
    var io_context = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_context.deinit();
    const key_pair = StdEd25519.KeyPair.generate(io_context.io());
    return .{
        .public_key = key_pair.public_key.toBytes(),
        .secret_key = key_pair.secret_key.toBytes(),
    };
}

/// Signs message with secret_key.
/// Ownership: the returned fixed-size signature is an inline value and requires no release.
pub fn sign(secret_key: SecretKey, message: []const u8) Error!Signature {
    const key_pair = try KeyPair.fromSecretKey(secret_key);
    const raw_secret_key = try StdEd25519.SecretKey.fromBytes(key_pair.secret_key);
    const raw_key_pair = try StdEd25519.KeyPair.fromSecretKey(raw_secret_key);
    return (try raw_key_pair.sign(message, null)).toBytes();
}

/// Verifies an Ed25519 signature.
/// Ownership: no allocation is performed and the returned boolean requires no release.
pub fn verify(public_key: PublicKey, message: []const u8, signature: Signature) bool {
    const raw_public_key = StdEd25519.PublicKey.fromBytes(public_key) catch return false;
    const raw_signature = StdEd25519.Signature.fromBytes(signature);
    raw_signature.verify(message, raw_public_key) catch return false;
    return true;
}

test "RFC 8032 Ed25519 test vector one" {
    const seed = [_]u8{ 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60 };
    const expected_public_key = [_]u8{ 0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a };
    const expected_signature = [_]u8{ 0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b };

    const key_pair = try KeyPair.fromSeed(seed);
    try std.testing.expectEqual(expected_public_key, key_pair.public_key);
    try std.testing.expectEqual(expected_signature, try sign(key_pair.secret_key, ""));
    try std.testing.expect(verify(key_pair.public_key, "", expected_signature));
}

test "Ed25519 detects a changed message" {
    const key_pair = try KeyPair.fromSeed(@as([seed_length]u8, @splat(0x42)));
    const signature = try sign(key_pair.secret_key, "cryptobin");
    try std.testing.expect(verify(key_pair.public_key, "cryptobin", signature));
    try std.testing.expect(!verify(key_pair.public_key, "cryptobim", signature));
}
