const std = @import("std");
const cipher = @import("cipher.zig");
const blowfish = @import("crypto/blowfish.zig");

pub const Kind = enum { ecb, cbc, pcbc, cfb, ofb, ctr };
pub const Error = error{ InvalidIvLength, InvalidBlockLength } || cipher.Error || @import("crypto/tea.zig").Error || std.mem.Allocator.Error;

const BlockEngine = struct {
    algorithm: cipher.Algorithm,
    key: []const u8,
    tea_rounds: u32,
    blowfish_context: ?*const blowfish.Context,

    fn encryptBlock(self: BlockEngine, input: []const u8, output: []u8) Error!void {
        if (self.blowfish_context) |context| {
            var in_block: [blowfish.block_length]u8 = undefined;
            var out_block: [blowfish.block_length]u8 = undefined;
            @memcpy(&in_block, input);
            context.encrypt(&out_block, in_block);
            @memcpy(output, &out_block);
            return;
        }
        try cipher.encryptBlock(self.algorithm, self.key, input, output, self.tea_rounds);
    }

    fn decryptBlock(self: BlockEngine, input: []const u8, output: []u8) Error!void {
        if (self.blowfish_context) |context| {
            var in_block: [blowfish.block_length]u8 = undefined;
            var out_block: [blowfish.block_length]u8 = undefined;
            @memcpy(&in_block, input);
            context.decrypt(&out_block, in_block);
            @memcpy(output, &out_block);
            return;
        }
        try cipher.decryptBlock(self.algorithm, self.key, input, output, self.tea_rounds);
    }
};

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

/// Applies a block or stream mode to `input`.
/// Ownership: the returned ciphertext or plaintext is allocated with `allocator`; the caller must release it with `allocator.free`.
pub fn apply(allocator: std.mem.Allocator, algorithm: cipher.Algorithm, key: []const u8, input: []const u8, iv: []const u8, kind: Kind, encrypt: bool, tea_rounds: u32) Error![]u8 {
    try cipher.validateKey(algorithm, key);
    const block_size = cipher.blockLength(algorithm);
    if (kind != .ecb and iv.len != block_size) return error.InvalidIvLength;
    if ((kind == .ecb or kind == .cbc or kind == .pcbc) and input.len % block_size != 0) return error.InvalidBlockLength;
    // Blowfish key expansion costs 521 block encryptions, so expand once here
    // instead of once per block inside cipher.encryptBlock.
    var blowfish_context: blowfish.Context = undefined;
    if (algorithm == .blowfish) blowfish_context = blowfish.Context.init(key);
    const engine = BlockEngine{
        .algorithm = algorithm,
        .key = key,
        .tea_rounds = tea_rounds,
        .blowfish_context = if (algorithm == .blowfish) &blowfish_context else null,
    };
    const output = try allocator.alloc(u8, input.len);
    errdefer allocator.free(output);

    var feedback: [cipher.max_block_length]u8 = @splat(0);
    var counter: [cipher.max_block_length]u8 = @splat(0);
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
        var block: [cipher.max_block_length]u8 = @splat(0);
        @memcpy(block[0..size], source);

        switch (kind) {
            .ecb => if (encrypt) try engine.encryptBlock(source, destination) else try engine.decryptBlock(source, destination),
            .cbc => if (encrypt) {
                xorBlock(block[0..block_size], block[0..block_size], feedback[0..block_size]);
                try engine.encryptBlock(block[0..block_size], stream[0..block_size]);
                @memcpy(destination, stream[0..size]);
                feedback = stream;
            } else {
                try engine.decryptBlock(source, stream[0..block_size]);
                xorBlock(block[0..block_size], stream[0..block_size], feedback[0..block_size]);
                @memcpy(destination, block[0..size]);
                @memcpy(feedback[0..block_size], source);
            },
            .pcbc => if (encrypt) {
                xorBlock(block[0..block_size], block[0..block_size], feedback[0..block_size]);
                try engine.encryptBlock(block[0..block_size], stream[0..block_size]);
                @memcpy(destination, stream[0..size]);
                xorBlock(feedback[0..block_size], source, stream[0..block_size]);
            } else {
                try engine.decryptBlock(source, stream[0..block_size]);
                xorBlock(block[0..block_size], stream[0..block_size], feedback[0..block_size]);
                @memcpy(destination, block[0..size]);
                xorBlock(feedback[0..block_size], source, block[0..block_size]);
            },
            .cfb => {
                try engine.encryptBlock(feedback[0..block_size], stream[0..block_size]);
                xorBlock(block[0..size], source, stream[0..size]);
                @memcpy(destination, block[0..size]);
                if (encrypt) @memcpy(feedback[0..size], destination) else @memcpy(feedback[0..size], source);
            },
            .ofb => {
                try engine.encryptBlock(feedback[0..block_size], stream[0..block_size]);
                feedback = stream;
                xorBlock(block[0..size], source, stream[0..size]);
                @memcpy(destination, block[0..size]);
            },
            .ctr => {
                try engine.encryptBlock(counter[0..block_size], stream[0..block_size]);
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

test "blowfish cbc round trip" {
    const allocator = std.testing.allocator;
    const key = "0123456789abcdef";
    const iv = "12345678";
    const plain = "useData5useData5";
    const encrypted = try apply(allocator, .blowfish, key, plain, iv, .cbc, true, 64);
    defer allocator.free(encrypted);
    const decrypted = try apply(allocator, .blowfish, key, encrypted, iv, .cbc, false, 64);
    defer allocator.free(decrypted);
    try std.testing.expectEqualSlices(u8, plain, decrypted);
}
