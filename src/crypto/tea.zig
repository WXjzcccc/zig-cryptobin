const std = @import("std");

pub const block_length = 8;
pub const key_length = 16;
pub const Error = error{InvalidRounds};
const delta: u32 = 0x9e3779b9;

fn keyWords(key: [16]u8) [4]u32 {
    return .{
        std.mem.readInt(u32, key[0..4], .big),
        std.mem.readInt(u32, key[4..8], .big),
        std.mem.readInt(u32, key[8..12], .big),
        std.mem.readInt(u32, key[12..16], .big),
    };
}

/// Encrypts one TEA block into output.
/// Ownership: no allocation is performed; the caller owns and manages output.
pub fn encrypt(output: *[8]u8, input: [8]u8, key: [16]u8, rounds: u32) Error!void {
    if (rounds % 2 != 0) return error.InvalidRounds;
    const words = keyWords(key);
    var left = std.mem.readInt(u32, input[0..4], .big);
    var right = std.mem.readInt(u32, input[4..8], .big);
    var sum: u32 = 0;
    for (0..rounds / 2) |_| {
        sum +%= delta;
        left +%= ((right << 4) +% words[0]) ^ (right +% sum) ^ ((right >> 5) +% words[1]);
        right +%= ((left << 4) +% words[2]) ^ (left +% sum) ^ ((left >> 5) +% words[3]);
    }
    std.mem.writeInt(u32, output[0..4], left, .big);
    std.mem.writeInt(u32, output[4..8], right, .big);
}

/// Decrypts one TEA block into output.
/// Ownership: no allocation is performed; the caller owns and manages output.
pub fn decrypt(output: *[8]u8, input: [8]u8, key: [16]u8, rounds: u32) Error!void {
    if (rounds % 2 != 0) return error.InvalidRounds;
    const words = keyWords(key);
    var left = std.mem.readInt(u32, input[0..4], .big);
    var right = std.mem.readInt(u32, input[4..8], .big);
    var sum: u32 = delta *% (rounds / 2);
    for (0..rounds / 2) |_| {
        right -%= ((left << 4) +% words[2]) ^ (left +% sum) ^ ((left >> 5) +% words[3]);
        left -%= ((right << 4) +% words[0]) ^ (right +% sum) ^ ((right >> 5) +% words[1]);
        sum -%= delta;
    }
    std.mem.writeInt(u32, output[0..4], left, .big);
    std.mem.writeInt(u32, output[4..8], right, .big);
}

/// Encrypts one XTEA block into output.
/// Ownership: no allocation is performed; the caller owns and manages output.
pub fn encryptXtea(output: *[8]u8, input: [8]u8, key: [16]u8) void {
    const words = keyWords(key);
    var table: [64]u32 = undefined;
    var sum: u32 = 0;
    var index: usize = 0;
    while (index < 64) : (index += 2) {
        table[index] = sum +% words[sum & 3];
        sum +%= delta;
        table[index + 1] = sum +% words[(sum >> 11) & 3];
    }
    var left = std.mem.readInt(u32, input[0..4], .big);
    var right = std.mem.readInt(u32, input[4..8], .big);
    index = 0;
    while (index < 64) : (index += 2) {
        left +%= ((right << 4 ^ right >> 5) +% right) ^ table[index];
        right +%= ((left << 4 ^ left >> 5) +% left) ^ table[index + 1];
    }
    std.mem.writeInt(u32, output[0..4], left, .big);
    std.mem.writeInt(u32, output[4..8], right, .big);
}

/// Decrypts one XTEA block into output.
/// Ownership: no allocation is performed; the caller owns and manages output.
pub fn decryptXtea(output: *[8]u8, input: [8]u8, key: [16]u8) void {
    const words = keyWords(key);
    var table: [64]u32 = undefined;
    var sum: u32 = 0;
    var index: usize = 0;
    while (index < 64) : (index += 2) {
        table[index] = sum +% words[sum & 3];
        sum +%= delta;
        table[index + 1] = sum +% words[(sum >> 11) & 3];
    }
    var left = std.mem.readInt(u32, input[0..4], .big);
    var right = std.mem.readInt(u32, input[4..8], .big);
    index = 64;
    while (index > 0) {
        index -= 1;
        right -%= ((left << 4 ^ left >> 5) +% left) ^ table[index];
        index -= 1;
        left -%= ((right << 4 ^ right >> 5) +% right) ^ table[index];
    }
    std.mem.writeInt(u32, output[0..4], left, .big);
    std.mem.writeInt(u32, output[4..8], right, .big);
}

test "TEA standard vector" {
    const key: [16]u8 = @splat(0);
    const input: [8]u8 = @splat(0);
    var output: [8]u8 = undefined;
    try encrypt(&output, input, key, 64);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x41, 0xea, 0x3a, 0x0a, 0x94, 0xba, 0xa9, 0x40 }, &output);
    var recovered: [8]u8 = undefined;
    try decrypt(&recovered, output, key, 64);
    try std.testing.expectEqualSlices(u8, &input, &recovered);
}

test "Go x/crypto TEA and XTEA vectors" {
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const input = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var encrypted: [8]u8 = undefined;
    try encrypt(&encrypted, input, key, 64);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x54, 0xd5, 0x1b, 0x2b, 0xf3, 0xe4, 0x7e, 0x12 }, &encrypted);

    encryptXtea(&encrypted, input, key);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xff, 0xc5, 0x2d, 0x10, 0xa0, 0x10, 0x01, 0x0b }, &encrypted);
    var recovered: [8]u8 = undefined;
    decryptXtea(&recovered, encrypted, key);
    try std.testing.expectEqualSlices(u8, &input, &recovered);
}
