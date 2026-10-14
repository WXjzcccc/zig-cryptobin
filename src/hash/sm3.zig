const std = @import("std");

pub const Sm3 = struct {
    const Self = @This();

    pub const digest_length = 32;
    pub const block_length = 64;

    state: [8]u32,
    buffer: [block_length]u8 = undefined,
    buffer_len: usize = 0,
    total_len: u64 = 0,

    /// Initializes an SM3 hashing context.
    /// Ownership: the returned context is an inline value and requires no release.
    pub fn init(_: anytype) Self {
        return .{
            .state = .{
                0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
            },
        };
    }

    /// Adds input to this incremental SM3 context.
    /// Ownership: no allocation is performed and the input slice remains caller-owned.
    pub fn update(self: *Self, input: []const u8) void {
        self.total_len +%= @intCast(input.len);
        var remaining = input;

        if (self.buffer_len > 0) {
            const amount = @min(block_length - self.buffer_len, remaining.len);
            @memcpy(self.buffer[self.buffer_len..][0..amount], remaining[0..amount]);
            self.buffer_len += amount;
            remaining = remaining[amount..];
            if (self.buffer_len == block_length) {
                self.compress(self.buffer);
                self.buffer_len = 0;
            }
        }

        while (remaining.len >= block_length) {
            self.compress(remaining[0..block_length].*);
            remaining = remaining[block_length..];
        }

        if (remaining.len > 0) {
            @memcpy(self.buffer[0..remaining.len], remaining);
            self.buffer_len = remaining.len;
        }
    }

    /// Finalizes a copy of the context and writes the digest into output.
    /// Ownership: no allocation is performed; the caller owns and manages output.
    pub fn final(self: *const Self, output: *[digest_length]u8) void {
        var copy = self.*;
        const bit_len = copy.total_len *% 8;
        copy.update(&[_]u8{0x80});

        const zeros: [block_length]u8 = @splat(0);
        const zero_len = if (copy.buffer_len <= 56) 56 - copy.buffer_len else block_length + 56 - copy.buffer_len;
        copy.update(zeros[0..zero_len]);

        var length_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &length_bytes, bit_len, .big);
        copy.update(&length_bytes);

        for (copy.state, 0..) |word, index| {
            std.mem.writeInt(u32, output[index * 4 ..][0..4], word, .big);
        }
    }

    /// Computes an SM3 digest in the caller-provided output buffer.
    /// Ownership: no allocation is performed; the caller owns and manages output.
    pub fn hash(input: []const u8, output: []u8, _: anytype) void {
        std.debug.assert(output.len >= digest_length);
        var context = Self.init(.{});
        context.update(input);
        var digest: [digest_length]u8 = undefined;
        context.final(&digest);
        @memcpy(output[0..digest_length], &digest);
    }

    fn compress(self: *Self, input: [block_length]u8) void {
        var words: [68]u32 = undefined;
        for (0..16) |index| {
            words[index] = std.mem.readInt(u32, input[index * 4 ..][0..4], .big);
        }
        for (16..68) |index| {
            words[index] = p1(words[index - 16] ^ words[index - 9] ^ std.math.rotl(u32, words[index - 3], 15)) ^ std.math.rotl(u32, words[index - 13], 7) ^ words[index - 6];
        }

        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];
        var f = self.state[5];
        var g = self.state[6];
        var h = self.state[7];

        for (0..64) |round| {
            const constant: u32 = if (round < 16) 0x79cc4519 else 0x7a879d8a;
            const ss1 = std.math.rotl(u32, std.math.rotl(u32, a, 12) +% e +% std.math.rotl(u32, constant, @as(u5, @truncate(round))), 7);
            const ss2 = ss1 ^ std.math.rotl(u32, a, 12);
            const ff = if (round < 16) a ^ b ^ c else (a & b) | (a & c) | (b & c);
            const gg = if (round < 16) e ^ f ^ g else ((f ^ g) & e) ^ g;
            const tt1 = ff +% d +% ss2 +% (words[round] ^ words[round + 4]);
            const tt2 = gg +% h +% ss1 +% words[round];

            d = c;
            c = std.math.rotl(u32, b, 9);
            b = a;
            a = tt1;
            h = g;
            g = std.math.rotl(u32, f, 19);
            f = e;
            e = p0(tt2);
        }

        self.state[0] ^= a;
        self.state[1] ^= b;
        self.state[2] ^= c;
        self.state[3] ^= d;
        self.state[4] ^= e;
        self.state[5] ^= f;
        self.state[6] ^= g;
        self.state[7] ^= h;
    }
};

pub const HmacSm3 = std.crypto.auth.hmac.Hmac(Sm3);

/// Computes an SM3 digest as a fixed-size array.
/// Ownership: the returned array is an inline value and requires no release.
pub fn sum(input: []const u8) [Sm3.digest_length]u8 {
    var output: [Sm3.digest_length]u8 = undefined;
    Sm3.hash(input, &output, .{});
    return output;
}

fn p0(value: u32) u32 {
    return value ^ std.math.rotl(u32, value, 9) ^ std.math.rotl(u32, value, 17);
}

fn p1(value: u32) u32 {
    return value ^ std.math.rotl(u32, value, 15) ^ std.math.rotl(u32, value, 23);
}

test "SM3 GM/T 0004 abc test vector" {
    const expected = [_]u8{ 0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0 };
    try std.testing.expectEqual(expected, sum("abc"));
}

test "SM3 supports incremental updates" {
    const expected = [_]u8{ 0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32 };
    var context = Sm3.init(.{});
    context.update("abcd");
    context.update("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
    var output: [Sm3.digest_length]u8 = undefined;
    context.final(&output);
    try std.testing.expectEqual(expected, output);
}

test "HMAC-SM3 matches go-cryptobin" {
    const expected = [_]u8{ 0x0a, 0x69, 0x40, 0x1a, 0x75, 0xc5, 0xd4, 0x71, 0xf5, 0x16, 0x64, 0x65, 0xee, 0xc8, 0x9e, 0x6a, 0x65, 0x19, 0x8a, 0xe8, 0x85, 0xc1, 0xfd, 0xc0, 0x61, 0x55, 0x62, 0x54, 0xd9, 0x1c, 0x10, 0x80 };
    var output: [Sm3.digest_length]u8 = undefined;
    HmacSm3.create(&output, "abc", "1234567812345678");
    try std.testing.expectEqual(expected, output);
}
