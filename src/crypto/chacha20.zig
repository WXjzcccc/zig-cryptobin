const std = @import("std");

pub const Error = error{OutputLengthMismatch};

fn quarterRound(state: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
    state[a] +%= state[b];
    state[d] = std.math.rotl(u32, state[d] ^ state[a], 16);
    state[c] +%= state[d];
    state[b] = std.math.rotl(u32, state[b] ^ state[c], 12);
    state[a] +%= state[b];
    state[d] = std.math.rotl(u32, state[d] ^ state[a], 8);
    state[c] +%= state[d];
    state[b] = std.math.rotl(u32, state[b] ^ state[c], 7);
}

fn block(output: *[64]u8, counter: u32, key: [32]u8, nonce: [12]u8) void {
    var state: [16]u32 = .{
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        undefined,  undefined,  undefined,  undefined,
        undefined,  undefined,  undefined,  undefined,
        counter,    undefined,  undefined,  undefined,
    };
    for (0..8) |index| state[4 + index] = std.mem.readInt(u32, key[index * 4 ..][0..4], .little);
    for (0..3) |index| state[13 + index] = std.mem.readInt(u32, nonce[index * 4 ..][0..4], .little);

    var working = state;
    for (0..10) |_| {
        quarterRound(&working, 0, 4, 8, 12);
        quarterRound(&working, 1, 5, 9, 13);
        quarterRound(&working, 2, 6, 10, 14);
        quarterRound(&working, 3, 7, 11, 15);
        quarterRound(&working, 0, 5, 10, 15);
        quarterRound(&working, 1, 6, 11, 12);
        quarterRound(&working, 2, 7, 8, 13);
        quarterRound(&working, 3, 4, 9, 14);
    }
    for (&working, state, 0..) |*value, initial, index| {
        value.* +%= initial;
        std.mem.writeInt(u32, output[index * 4 ..][0..4], value.*, .little);
    }
}

/// XORs input with the ChaCha20 keystream and writes into output.
/// Ownership: no allocation is performed; the caller owns and manages output.
pub fn xor(output: []u8, input: []const u8, counter: u32, key: [32]u8, nonce: [12]u8) Error!void {
    if (output.len != input.len) return error.OutputLengthMismatch;
    var current_counter = counter;
    var offset: usize = 0;
    while (offset < input.len) : (offset += 64) {
        var stream: [64]u8 = undefined;
        block(&stream, current_counter, key, nonce);
        current_counter +%= 1;
        const amount = @min(64, input.len - offset);
        for (output[offset .. offset + amount], input[offset .. offset + amount], stream[0..amount]) |*value, source, mask| value.* = source ^ mask;
    }
}

test "rfc 8439 chacha20 block" {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    const nonce = [_]u8{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };
    var output: [64]u8 = undefined;
    try xor(&output, &@as([64]u8, @splat(0)), 1, key, nonce);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    }, &output);
}
