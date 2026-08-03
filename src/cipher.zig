const std = @import("std");
const aes192 = @import("crypto/aes192.zig");
const des = @import("crypto/des.zig");
const rc4 = @import("crypto/rc4.zig");
const tea = @import("crypto/tea.zig");
const sm4 = @import("crypto/sm4.zig");

pub const Algorithm = enum {
    aes,
    des,
    two_des,
    triple_des,
    rc4,
    rc4_md5,
    tea,
    xtea,
    sm4,
    chacha20,
    chacha20_poly1305,
    xchacha20_poly1305,
};

pub const Error = error{ InvalidKeyLength, InvalidBlockLength };
pub const max_block_length = 16;

pub fn blockLength(algorithm: Algorithm) usize {
    return switch (algorithm) {
        .des, .two_des, .triple_des, .tea, .xtea => des.block_length,
        else => 16,
    };
}

pub fn validateKey(algorithm: Algorithm, key: []const u8) Error!void {
    switch (algorithm) {
        .aes => if (key.len != 16 and key.len != 24 and key.len != 32) return error.InvalidKeyLength,
        .des => if (key.len != 8) return error.InvalidKeyLength,
        .two_des => if (key.len != 16) return error.InvalidKeyLength,
        .triple_des => if (key.len != 24) return error.InvalidKeyLength,
        .rc4, .rc4_md5 => if (key.len == 0 or key.len > 256) return error.InvalidKeyLength,
        .tea, .xtea => if (key.len != 16) return error.InvalidKeyLength,
        .sm4 => if (key.len != 16) return error.InvalidKeyLength,
        .chacha20, .chacha20_poly1305, .xchacha20_poly1305 => if (key.len != 32) return error.InvalidKeyLength,
    }
}

pub fn encryptBlock(algorithm: Algorithm, key: []const u8, input: []const u8, output: []u8, tea_rounds: u32) (Error || tea.Error)!void {
    if (input.len != blockLength(algorithm) or output.len != blockLength(algorithm)) return error.InvalidBlockLength;
    try validateKey(algorithm, key);
    if (algorithm == .tea or algorithm == .xtea) {
        var in_block: [8]u8 = undefined;
        var out_block: [8]u8 = undefined;
        var fixed_key: [16]u8 = undefined;
        @memcpy(&in_block, input);
        @memcpy(&fixed_key, key);
        if (algorithm == .tea) try tea.encrypt(&out_block, in_block, fixed_key, tea_rounds) else tea.encryptXtea(&out_block, in_block, fixed_key);
        @memcpy(output, &out_block);
        return;
    }
    if (algorithm == .sm4) {
        var in_block: [16]u8 = undefined;
        var out_block: [16]u8 = undefined;
        var fixed_key: [16]u8 = undefined;
        @memcpy(&in_block, input);
        @memcpy(&fixed_key, key);
        sm4.encrypt(&out_block, in_block, fixed_key);
        @memcpy(output, &out_block);
        return;
    }
    if (algorithm == .des or algorithm == .two_des or algorithm == .triple_des) {
        var in_block: [8]u8 = undefined;
        var out_block: [8]u8 = undefined;
        @memcpy(&in_block, input);
        if (algorithm == .des) {
            var fixed_key: [8]u8 = undefined;
            @memcpy(&fixed_key, key);
            des.encrypt(&out_block, in_block, fixed_key);
        } else {
            var first: [8]u8 = undefined;
            var second: [8]u8 = undefined;
            var third: [8]u8 = undefined;
            @memcpy(&first, key[0..8]);
            @memcpy(&second, key[8..16]);
            if (algorithm == .two_des) @memcpy(&third, key[0..8]) else @memcpy(&third, key[16..24]);
            des.encryptTriple(&out_block, in_block, first, second, third);
        }
        @memcpy(output, &out_block);
        return;
    }
    var in_block: [max_block_length]u8 = undefined;
    var out_block: [max_block_length]u8 = undefined;
    @memcpy(&in_block, input);
    switch (algorithm) {
        .aes => if (key.len == 16) {
            var k: [16]u8 = undefined;
            @memcpy(&k, key);
            var ctx = std.crypto.core.aes.Aes128.initEnc(k);
            ctx.encrypt(&out_block, &in_block);
        } else if (key.len == 24) {
            var k: [24]u8 = undefined;
            @memcpy(&k, key);
            aes192.encrypt(&out_block, in_block, k);
        } else {
            var k: [32]u8 = undefined;
            @memcpy(&k, key);
            var ctx = std.crypto.core.aes.Aes256.initEnc(k);
            ctx.encrypt(&out_block, &in_block);
        },
        else => return error.InvalidKeyLength,
    }
    @memcpy(output, &out_block);
}

pub fn decryptBlock(algorithm: Algorithm, key: []const u8, input: []const u8, output: []u8, tea_rounds: u32) (Error || tea.Error)!void {
    if (input.len != blockLength(algorithm) or output.len != blockLength(algorithm)) return error.InvalidBlockLength;
    try validateKey(algorithm, key);
    if (algorithm == .tea or algorithm == .xtea) {
        var in_block: [8]u8 = undefined;
        var out_block: [8]u8 = undefined;
        var fixed_key: [16]u8 = undefined;
        @memcpy(&in_block, input);
        @memcpy(&fixed_key, key);
        if (algorithm == .tea) try tea.decrypt(&out_block, in_block, fixed_key, tea_rounds) else tea.decryptXtea(&out_block, in_block, fixed_key);
        @memcpy(output, &out_block);
        return;
    }
    if (algorithm == .sm4) {
        var in_block: [16]u8 = undefined;
        var out_block: [16]u8 = undefined;
        var fixed_key: [16]u8 = undefined;
        @memcpy(&in_block, input);
        @memcpy(&fixed_key, key);
        sm4.decrypt(&out_block, in_block, fixed_key);
        @memcpy(output, &out_block);
        return;
    }
    if (algorithm == .des or algorithm == .two_des or algorithm == .triple_des) {
        var in_block: [8]u8 = undefined;
        var out_block: [8]u8 = undefined;
        @memcpy(&in_block, input);
        if (algorithm == .des) {
            var fixed_key: [8]u8 = undefined;
            @memcpy(&fixed_key, key);
            des.decrypt(&out_block, in_block, fixed_key);
        } else {
            var first: [8]u8 = undefined;
            var second: [8]u8 = undefined;
            var third: [8]u8 = undefined;
            @memcpy(&first, key[0..8]);
            @memcpy(&second, key[8..16]);
            if (algorithm == .two_des) @memcpy(&third, key[0..8]) else @memcpy(&third, key[16..24]);
            des.decryptTriple(&out_block, in_block, first, second, third);
        }
        @memcpy(output, &out_block);
        return;
    }
    var in_block: [max_block_length]u8 = undefined;
    var out_block: [max_block_length]u8 = undefined;
    @memcpy(&in_block, input);
    switch (algorithm) {
        .aes => if (key.len == 16) {
            var k: [16]u8 = undefined;
            @memcpy(&k, key);
            var ctx = std.crypto.core.aes.Aes128.initDec(k);
            ctx.decrypt(&out_block, &in_block);
        } else if (key.len == 24) {
            var k: [24]u8 = undefined;
            @memcpy(&k, key);
            aes192.decrypt(&out_block, in_block, k);
        } else {
            var k: [32]u8 = undefined;
            @memcpy(&k, key);
            var ctx = std.crypto.core.aes.Aes256.initDec(k);
            ctx.decrypt(&out_block, &in_block);
        },
        else => return error.InvalidKeyLength,
    }
    @memcpy(output, &out_block);
}

test "aes block vector" {
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const plain = [_]u8{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
    const expected = [_]u8{ 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };
    var actual: [16]u8 = undefined;
    try encryptBlock(.aes, &key, &plain, &actual, 64);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}
