const std = @import("std");

pub const Error = error{InvalidKeyLength} || std.mem.Allocator.Error;

/// Computes an AES-CMAC with a 128- or 256-bit key.
/// Ownership: the returned 16-byte tag is allocated with `allocator`; the caller must release it with `allocator.free`.
pub fn cmacAes(allocator: std.mem.Allocator, key: []const u8, message: []const u8) Error![]u8 {
    const output = try allocator.alloc(u8, 16);
    if (key.len == 16) {
        var fixed_key: [16]u8 = undefined;
        @memcpy(&fixed_key, key);
        std.crypto.auth.cmac.CmacAes128.create(@ptrCast(output.ptr), message, &fixed_key);
    } else if (key.len == 32) {
        var fixed_key: [32]u8 = undefined;
        @memcpy(&fixed_key, key);
        const CmacAes256 = std.crypto.auth.cmac.Cmac(std.crypto.core.aes.Aes256);
        CmacAes256.create(@ptrCast(output.ptr), message, &fixed_key);
    } else {
        allocator.free(output);
        return error.InvalidKeyLength;
    }
    return output;
}

test "RFC 4493 AES-CMAC" {
    const allocator = std.testing.allocator;
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const message = [_]u8{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    const tag = try cmacAes(allocator, &key, &message);
    defer allocator.free(tag);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c }, tag);
}
