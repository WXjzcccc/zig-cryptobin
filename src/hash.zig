const std = @import("std");
const sm3 = @import("hash/sm3.zig");

pub const Kind = enum { md5, sha1, sha256, sha512, sha3_256, sha3_512, sm3 };
pub const Error = std.mem.Allocator.Error || error{UnsupportedHash};

pub fn digestLength(kind: Kind) usize {
    return switch (kind) {
        .md5 => std.crypto.hash.Md5.digest_length,
        .sha1 => std.crypto.hash.Sha1.digest_length,
        .sha256 => std.crypto.hash.sha2.Sha256.digest_length,
        .sha512 => std.crypto.hash.sha2.Sha512.digest_length,
        .sha3_256 => std.crypto.hash.sha3.Sha3_256.digest_length,
        .sha3_512 => std.crypto.hash.sha3.Sha3_512.digest_length,
        .sm3 => sm3.Sm3.digest_length,
    };
}

pub fn digest(allocator: std.mem.Allocator, kind: Kind, input: []const u8) Error![]u8 {
    const output = try allocator.alloc(u8, digestLength(kind));
    switch (kind) {
        .md5 => std.crypto.hash.Md5.hash(input, @ptrCast(output.ptr), .{}),
        .sha1 => std.crypto.hash.Sha1.hash(input, @ptrCast(output.ptr), .{}),
        .sha256 => std.crypto.hash.sha2.Sha256.hash(input, @ptrCast(output.ptr), .{}),
        .sha512 => std.crypto.hash.sha2.Sha512.hash(input, @ptrCast(output.ptr), .{}),
        .sha3_256 => std.crypto.hash.sha3.Sha3_256.hash(input, @ptrCast(output.ptr), .{}),
        .sha3_512 => std.crypto.hash.sha3.Sha3_512.hash(input, @ptrCast(output.ptr), .{}),
        .sm3 => sm3.Sm3.hash(input, output, .{}),
    }
    return output;
}

pub fn hmac(allocator: std.mem.Allocator, kind: Kind, key: []const u8, input: []const u8) Error![]u8 {
    const output = try allocator.alloc(u8, digestLength(kind));
    switch (kind) {
        .md5 => std.crypto.auth.hmac.HmacMd5.create(@ptrCast(output.ptr), input, key),
        .sha1 => std.crypto.auth.hmac.HmacSha1.create(@ptrCast(output.ptr), input, key),
        .sha256 => std.crypto.auth.hmac.sha2.HmacSha256.create(@ptrCast(output.ptr), input, key),
        .sha512 => std.crypto.auth.hmac.sha2.HmacSha512.create(@ptrCast(output.ptr), input, key),
        .sm3 => sm3.HmacSm3.create(@ptrCast(output.ptr), input, key),
        .sha3_256, .sha3_512 => {
            allocator.free(output);
            return error.UnsupportedHash;
        },
    }
    return output;
}

test "SM3 is available through the shared hash API" {
    const output = try digest(std.testing.allocator, .sm3, "abc");
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
    }, output);
}

test "sha256 and hmac" {
    const allocator = std.testing.allocator;
    const sum = try digest(allocator, .sha256, "abc");
    defer allocator.free(sum);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    }, sum);

    const mac = try hmac(allocator, .sha256, "key", "The quick brown fox jumps over the lazy dog");
    defer allocator.free(mac);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
        0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8,
    }, mac);
}
