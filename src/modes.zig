const std = @import("std");
const cipher = @import("cipher.zig");

pub const Kind = enum { ecb, cbc, pcbc, cfb, ofb, ctr };
pub const Error = error{ InvalidIvLength, InvalidBlockLength } || cipher.Error || @import("crypto/tea.zig").Error || std.mem.Allocator.Error;

fn xorBlock(out: []u8, left: []const u8, right: []const u8) void {
    for (out, left, right) |*value, a, b| value.* = a ^ b;
}

fn incrementCounter(counter: []u8) void {
    var index = counter.len;
    while (index > 0) {
        index -= 1;
        counter[index] +%= 1;
        if (counter[index] != 0) break;
    }
}

pub fn apply(allocator: std.mem.Allocator, algorithm: cipher.Algorithm, key: []const u8, input: []const u8, iv: []const u8, kind: Kind, encrypt: bool, tea_rounds: u32) Error![]u8 {
    try cipher.validateKey(algorithm, key);
    const block_size = cipher.blockLength(algorithm);
    if (kind != .ecb and iv.len != block_size) return error.InvalidIvLength;
    if ((kind == .ecb or kind == .cbc or kind == .pcbc) and input.len % block_size != 0) return error.InvalidBlockLength;
    const output = try allocator.alloc(u8, input.len);
    errdefer allocator.free(output);

    var feedback: [cipher.max_block_length]u8 = [_]u8{0} ** cipher.max_block_length;
    var counter: [cipher.max_block_length]u8 = [_]u8{0} ** cipher.max_block_length;
    if (kind != .ecb) {
        @memcpy(feedback[0..block_size], iv);
        @memcpy(counter[0..block_size], iv);
    }

    var index: usize = 0;
    while (index < input.len) : (index += block_size) {
        const size = @min(block_size, input.len - index);
        const source = input[index .. index + size];
        const destination = output[index .. index + size];
        var stream: [cipher.max_block_length]u8 = undefined;
        var block: [cipher.max_block_length]u8 = [_]u8{0} ** cipher.max_block_length;
        @memcpy(block[0..size], source);

        switch (kind) {
            .ecb => if (encrypt) try cipher.encryptBlock(algorithm, key, source, destination, tea_rounds) else try cipher.decryptBlock(algorithm, key, source, destination, tea_rounds),
            .cbc => if (encrypt) {
                xorBlock(block[0..block_size], block[0..block_size], feedback[0..block_size]);
                try cipher.encryptBlock(algorithm, key, block[0..block_size], stream[0..block_size], tea_rounds);
                @memcpy(destination, stream[0..size]);
                feedback = stream;
            } else {
                try cipher.decryptBlock(algorithm, key, source, stream[0..block_size], tea_rounds);
                xorBlock(block[0..block_size], stream[0..block_size], feedback[0..block_size]);
                @memcpy(destination, block[0..size]);
                @memcpy(feedback[0..block_size], source);
            },
            .pcbc => if (encrypt) {
                xorBlock(block[0..block_size], block[0..block_size], feedback[0..block_size]);
                try cipher.encryptBlock(algorithm, key, block[0..block_size], stream[0..block_size], tea_rounds);
                @memcpy(destination, stream[0..size]);
                xorBlock(feedback[0..block_size], source, stream[0..block_size]);
            } else {
                try cipher.decryptBlock(algorithm, key, source, stream[0..block_size], tea_rounds);
                xorBlock(block[0..block_size], stream[0..block_size], feedback[0..block_size]);
                @memcpy(destination, block[0..size]);
                xorBlock(feedback[0..block_size], source, block[0..block_size]);
            },
            .cfb => {
                try cipher.encryptBlock(algorithm, key, feedback[0..block_size], stream[0..block_size], tea_rounds);
                xorBlock(block[0..size], source, stream[0..size]);
                @memcpy(destination, block[0..size]);
                if (encrypt) @memcpy(feedback[0..size], destination) else @memcpy(feedback[0..size], source);
            },
            .ofb => {
                try cipher.encryptBlock(algorithm, key, feedback[0..block_size], stream[0..block_size], tea_rounds);
                feedback = stream;
                xorBlock(block[0..size], source, stream[0..size]);
                @memcpy(destination, block[0..size]);
            },
            .ctr => {
                try cipher.encryptBlock(algorithm, key, counter[0..block_size], stream[0..block_size], tea_rounds);
                incrementCounter(counter[0..block_size]);
                xorBlock(block[0..size], source, stream[0..size]);
                @memcpy(destination, block[0..size]);
            },
        }
    }
    return output;
}

test "cbc round trip" {
    const allocator = std.testing.allocator;
    const key = "dfertf12dfertf12";
    const iv = "1234567890abcdef";
    const plain = "useData5useData5";
    const encrypted = try apply(allocator, .aes, key, plain, iv, .cbc, true, 64);
    defer allocator.free(encrypted);
    const decrypted = try apply(allocator, .aes, key, encrypted, iv, .cbc, false, 64);
    defer allocator.free(decrypted);
    try std.testing.expectEqualSlices(u8, plain, decrypted);
}
