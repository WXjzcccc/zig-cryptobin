const std = @import("std");

pub const Error = error{ InvalidBase64, InvalidHex } || std.mem.Allocator.Error;

pub fn base64Encode(allocator: std.mem.Allocator, input: []const u8) Error![]u8 {
    const size = std.base64.standard.Encoder.calcSize(input.len);
    const output = try allocator.alloc(u8, size);
    _ = std.base64.standard.Encoder.encode(output, input);
    return output;
}

pub fn base64Decode(allocator: std.mem.Allocator, input: []const u8) Error![]u8 {
    const size = std.base64.standard.Decoder.calcSizeForSlice(input) catch return error.InvalidBase64;
    const output = try allocator.alloc(u8, size);
    errdefer allocator.free(output);
    std.base64.standard.Decoder.decode(output, input) catch return error.InvalidBase64;
    return output;
}

pub fn hexEncode(allocator: std.mem.Allocator, input: []const u8) Error![]u8 {
    const output = try allocator.alloc(u8, input.len * 2);
    const alphabet = "0123456789abcdef";
    for (input, 0..) |value, index| {
        output[index * 2] = alphabet[value >> 4];
        output[index * 2 + 1] = alphabet[value & 0x0f];
    }
    return output;
}

pub fn hexDecode(allocator: std.mem.Allocator, input: []const u8) Error![]u8 {
    if (input.len % 2 != 0) return error.InvalidHex;
    const output = try allocator.alloc(u8, input.len / 2);
    errdefer allocator.free(output);
    _ = std.fmt.hexToBytes(output, input) catch return error.InvalidHex;
    return output;
}

test "encoding round trip" {
    const allocator = std.testing.allocator;
    const bytes = "cryptobin";
    const encoded = try base64Encode(allocator, bytes);
    defer allocator.free(encoded);
    const decoded = try base64Decode(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, bytes, decoded);

    const hex = try hexEncode(allocator, bytes);
    defer allocator.free(hex);
    const unhex = try hexDecode(allocator, hex);
    defer allocator.free(unhex);
    try std.testing.expectEqualSlices(u8, bytes, unhex);
}
