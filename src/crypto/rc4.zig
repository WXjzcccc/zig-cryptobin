const std = @import("std");

pub const Error = error{InvalidKeyLength};

pub fn xor(output: []u8, input: []const u8, key: []const u8) Error!void {
    if (key.len == 0 or key.len > 256) return error.InvalidKeyLength;
    if (output.len != input.len) return error.InvalidKeyLength;
    var state: [256]u8 = undefined;
    for (&state, 0..) |*value, index| value.* = @intCast(index);

    var j: u8 = 0;
    for (&state, 0..) |*value, index| {
        j +%= value.* +% key[index % key.len];
        std.mem.swap(u8, value, &state[j]);
    }

    var i: u8 = 0;
    j = 0;
    for (output, input) |*destination, source| {
        i +%= 1;
        j +%= state[i];
        std.mem.swap(u8, &state[i], &state[j]);
        destination.* = source ^ state[state[i] +% state[j]];
    }
}

test "RFC 6229 RC4 vector" {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    var actual: [16]u8 = undefined;
    try xor(&actual, &[_]u8{0} ** 16, &key);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
        0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8,
    }, &actual);
}
