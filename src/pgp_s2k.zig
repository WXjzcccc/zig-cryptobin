const std = @import("std");

pub const Hash = enum { md5, sha1, sha256, sha512 };
pub const Error = error{MissingSaltForIteration} || std.mem.Allocator.Error;

/// Derives an OpenPGP S2K key using `hash`.
/// Ownership: the returned key bytes are allocated with `allocator`; the caller must release them with `allocator.free`.
pub fn derive(allocator: std.mem.Allocator, hash: Hash, password: []const u8, salt: []const u8, iterations: usize, length: usize) Error![]u8 {
    if (iterations > 1 and salt.len == 0) return error.MissingSaltForIteration;
    return switch (hash) {
        .md5 => deriveWithHash(std.crypto.hash.Md5, allocator, password, salt, iterations, length),
        .sha1 => deriveWithHash(std.crypto.hash.Sha1, allocator, password, salt, iterations, length),
        .sha256 => deriveWithHash(std.crypto.hash.sha2.Sha256, allocator, password, salt, iterations, length),
        .sha512 => deriveWithHash(std.crypto.hash.sha2.Sha512, allocator, password, salt, iterations, length),
    };
}

fn deriveWithHash(comptime Digest: type, allocator: std.mem.Allocator, password: []const u8, salt: []const u8, iterations: usize, length: usize) std.mem.Allocator.Error![]u8 {
    const output = try allocator.alloc(u8, length);
    errdefer allocator.free(output);
    const input_length = salt.len + password.len;
    const input = try allocator.alloc(u8, input_length);
    defer allocator.free(input);
    @memcpy(input[0..salt.len], salt);
    @memcpy(input[salt.len..], password);

    var generated: usize = 0;
    var pass: usize = 0;
    while (generated < length) : (pass += 1) {
        var context = Digest.init(.{});
        var zero_count = pass;
        const zeros: [64]u8 = @splat(0);
        while (zero_count > 0) {
            const amount = @min(zero_count, zeros.len);
            context.update(zeros[0..amount]);
            zero_count -= amount;
        }
        if (input.len > 0) {
            var remaining = @max(iterations, input.len);
            while (remaining > 0) {
                const amount = @min(remaining, input.len);
                context.update(input[0..amount]);
                remaining -= amount;
            }
        }
        var digest: [Digest.digest_length]u8 = undefined;
        context.final(&digest);
        const amount = @min(digest.len, length - generated);
        @memcpy(output[generated .. generated + amount], digest[0..amount]);
        generated += amount;
    }
    return output;
}

test "OpenPGP S2K simple and iterated vectors" {
    const allocator = std.testing.allocator;
    const simple = try derive(allocator, .sha1, "password", "", 1, 16);
    defer allocator.free(simple);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x5b, 0xaa, 0x61, 0xe4, 0xc9, 0xb9, 0x3f, 0x3f, 0x06, 0x82, 0x25, 0x0b, 0x6c, 0xf8, 0x33, 0x1b }, simple);

    const iterated = try derive(allocator, .sha256, "password", "12345678", 65536, 32);
    defer allocator.free(iterated);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xa4, 0xb9, 0x95, 0xad, 0x2c, 0x2a, 0x79, 0xee, 0x68, 0xc9, 0x41, 0xef, 0xc8, 0x2a, 0x62, 0xe6,
        0x02, 0x51, 0xd6, 0x80, 0x71, 0x0e, 0x40, 0xba, 0x7b, 0x64, 0xf0, 0x29, 0x22, 0x81, 0xa3, 0x69,
    }, iterated);
    try std.testing.expectError(error.MissingSaltForIteration, derive(allocator, .sha256, "password", "", 2, 16));
}
