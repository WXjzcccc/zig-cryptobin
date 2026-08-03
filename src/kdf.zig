const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{ WeakParameters, OutputTooLong, ScryptFailed, BcryptFailed };

fn pbkdf2(allocator: std.mem.Allocator, comptime Hmac: type, output: []u8, password: []const u8, salt: []const u8, rounds: u32) Error!void {
    if (rounds == 0) return error.WeakParameters;
    const block_count = std.math.divCeil(usize, output.len, Hmac.mac_length) catch unreachable;
    if (block_count > std.math.maxInt(u32)) return error.OutputTooLong;
    var block_index: usize = 1;
    while (block_index <= block_count) : (block_index += 1) {
        const initial = try allocator.alloc(u8, salt.len + 4);
        defer allocator.free(initial);
        @memcpy(initial[0..salt.len], salt);
        std.mem.writeInt(u32, initial[salt.len..][0..4], @intCast(block_index), .big);
        var previous: [Hmac.mac_length]u8 = undefined;
        Hmac.create(&previous, initial, password);
        var accumulated = previous;
        var iteration: u32 = 1;
        while (iteration < rounds) : (iteration += 1) {
            Hmac.create(&previous, &previous, password);
            for (&accumulated, previous) |*value, next| value.* ^= next;
        }
        const offset = (block_index - 1) * Hmac.mac_length;
        const amount = @min(Hmac.mac_length, output.len - offset);
        @memcpy(output[offset .. offset + amount], accumulated[0..amount]);
    }
}

pub fn pbkdf2Sha256(allocator: std.mem.Allocator, password: []const u8, salt: []const u8, rounds: u32, length: usize) Error![]u8 {
    const result = try allocator.alloc(u8, length);
    errdefer allocator.free(result);
    try pbkdf2(allocator, std.crypto.auth.hmac.sha2.HmacSha256, result, password, salt, rounds);
    return result;
}

pub fn pbkdf2Sha512(allocator: std.mem.Allocator, password: []const u8, salt: []const u8, rounds: u32, length: usize) Error![]u8 {
    const result = try allocator.alloc(u8, length);
    errdefer allocator.free(result);
    try pbkdf2(allocator, std.crypto.auth.hmac.sha2.HmacSha512, result, password, salt, rounds);
    return result;
}

pub fn hkdfSha256(allocator: std.mem.Allocator, salt: []const u8, ikm: []const u8, info: []const u8, length: usize) Error![]u8 {
    const result = try allocator.alloc(u8, length);
    const prk = std.crypto.kdf.hkdf.HkdfSha256.extract(salt, ikm);
    std.crypto.kdf.hkdf.HkdfSha256.expand(result, info, prk);
    return result;
}

pub fn scrypt(allocator: std.mem.Allocator, password: []const u8, salt: []const u8, cost: usize, block_size: u30, parallelization: u30, length: usize) Error![]u8 {
    if (cost < 2 or !std.math.isPowerOfTwo(cost)) return error.WeakParameters;
    const log_cost: u6 = @intCast(std.math.log2(cost));
    const output = try allocator.alloc(u8, length);
    errdefer allocator.free(output);
    const params = std.crypto.pwhash.scrypt.Params{ .ln = log_cost, .r = block_size, .p = parallelization };
    std.crypto.pwhash.scrypt.kdf(allocator, output, password, salt, params) catch |err| switch (err) {
        error.WeakParameters => return error.WeakParameters,
        error.OutputTooLong => return error.OutputTooLong,
        else => return error.ScryptFailed,
    };
    return output;
}

pub fn bcryptPbkdf(allocator: std.mem.Allocator, password: []const u8, salt: []const u8, rounds: u32, length: usize) Error![]u8 {
    if (rounds == 0 or password.len == 0 or salt.len == 0 or length == 0) return error.WeakParameters;
    const output = try allocator.alloc(u8, length);
    errdefer allocator.free(output);
    std.crypto.pwhash.bcrypt.pbkdf(password, salt, output, rounds) catch return error.BcryptFailed;
    return output;
}

pub fn bcryptOpenSshKdf(allocator: std.mem.Allocator, password: []const u8, salt: []const u8, rounds: u32, length: usize) Error![]u8 {
    if (rounds == 0 or password.len == 0 or salt.len == 0 or length == 0) return error.WeakParameters;
    const output = try allocator.alloc(u8, length);
    errdefer allocator.free(output);
    std.crypto.pwhash.bcrypt.opensshKdf(password, salt, output, rounds) catch return error.BcryptFailed;
    return output;
}

test "pbkdf2 rfc6070" {
    const allocator = std.testing.allocator;
    const result = try pbkdf2Sha256(allocator, "password", "salt", 1, 32);
    defer allocator.free(result);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
        0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b,
    }, result);
}

test "scrypt RFC 7914 vector" {
    const allocator = std.testing.allocator;
    const result = try scrypt(allocator, "", "", 16, 1, 1, 64);
    defer allocator.free(result);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97,
        0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42,
        0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
        0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28, 0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06,
    }, result);
}

test "bcrypt-pbkdf go-cryptobin vector" {
    const allocator = std.testing.allocator;
    const result = try bcryptPbkdf(allocator, "test password", "test salt", 4, 16);
    defer allocator.free(result);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x98, 0x6f, 0x10, 0x49, 0x8e, 0x60, 0x39, 0x0a, 0xed, 0xcd, 0x2b, 0xff, 0xb9, 0xa3, 0xed, 0xc0 }, result);
}

test "OpenSSH bcrypt KDF standard-library vector" {
    const allocator = std.testing.allocator;
    const result = try bcryptOpenSshKdf(allocator, "password", "salt", 5, 100);
    defer allocator.free(result);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        65,  207, 68,  58,  55,  252, 114, 141, 255, 65,  216, 175, 5,   92,  235, 68,  220, 92, 118, 161,
        40,  13,  241, 190, 56,  152, 69,  136, 41,  214, 51,  205, 37,  221, 101, 59,  105, 73, 133, 36,
        14,  59,  94,  212, 111, 107, 109, 237, 213, 235, 246, 119, 59,  76,  45,  130, 142, 81, 178, 231,
        161, 158, 138, 108, 18,  162, 26,  50,  218, 251, 23,  66,  2,   232, 20,  202, 216, 46, 12,  250,
        247, 246, 252, 23,  155, 74,  77,  195, 120, 113, 57,  88,  126, 81,  9,   249, 72,  18, 208, 160,
    }, result);
}
