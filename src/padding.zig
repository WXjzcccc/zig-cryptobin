const std = @import("std");

pub const Kind = enum {
    no_padding,
    zero,
    pkcs5,
    pkcs7,
    x923,
    iso10126,
    iso7816_4,
    iso97971,
    pboc2,
    tbc,
};

pub const Error = error{ InvalidPadding, InvalidBlockSize } || std.mem.Allocator.Error || std.Io.RandomSecureError;

fn fillSecureRandom(output: []u8) std.Io.RandomSecureError!void {
    var io_context = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_context.deinit();
    try io_context.io().randomSecure(output);
}

/// Adds `kind` padding to `input` for the given block size.
/// Ownership: the returned slice is allocated with `allocator`; the caller must release it with `allocator.free`.
pub fn add(allocator: std.mem.Allocator, input: []const u8, block_size: usize, kind: Kind) Error![]u8 {
    if (block_size == 0) return error.InvalidBlockSize;
    const remainder = input.len % block_size;
    const amount = if (kind == .no_padding) blk: {
        if (remainder != 0) return error.InvalidPadding;
        break :blk 0;
    } else block_size - remainder;
    const output = try allocator.alloc(u8, input.len + amount);
    @memcpy(output[0..input.len], input);
    if (amount == 0) return output;

    switch (kind) {
        .zero => @memset(output[input.len..], 0),
        .pkcs5, .pkcs7 => @memset(output[input.len..], @intCast(amount)),
        .x923, .pboc2 => {
            @memset(output[input.len .. output.len - 1], 0);
            output[output.len - 1] = @intCast(amount);
        },
        .iso10126 => {
            try fillSecureRandom(output[input.len .. output.len - 1]);
            output[output.len - 1] = @intCast(amount);
        },
        .iso7816_4, .iso97971 => {
            @memset(output[input.len..], 0);
            output[input.len] = 0x80;
        },
        .tbc => {
            const value: u8 = if (input.len == 0 or (input[input.len - 1] & 1) == 0) 0xff else 0x00;
            @memset(output[input.len..], value);
        },
        .no_padding => unreachable,
    }
    return output;
}

/// Validates and removes `kind` padding from `input`.
/// Ownership: the returned slice is allocated with `allocator`; the caller must release it with `allocator.free`.
pub fn remove(allocator: std.mem.Allocator, input: []const u8, block_size: usize, kind: Kind) Error![]u8 {
    if (kind == .no_padding) return allocator.dupe(u8, input);
    if (input.len == 0 or input.len % block_size != 0) return error.InvalidPadding;
    var amount: usize = 0;
    switch (kind) {
        .zero => {
            var plain_len = input.len;
            while (plain_len > 0 and input[plain_len - 1] == 0) plain_len -= 1;
            return allocator.dupe(u8, input[0..plain_len]);
        },
        .pkcs5, .pkcs7, .x923, .pboc2, .iso10126 => {
            amount = input[input.len - 1];
            if (amount == 0 or amount > block_size) return error.InvalidPadding;
            if (kind == .pkcs5 or kind == .pkcs7) {
                for (input[input.len - amount ..]) |value| if (value != amount) return error.InvalidPadding;
            } else if (kind != .iso10126) {
                for (input[input.len - amount .. input.len - 1]) |value| if (value != 0) return error.InvalidPadding;
            }
        },
        .iso7816_4, .iso97971 => {
            var index = input.len;
            while (index > 0 and input[index - 1] == 0) index -= 1;
            if (index == 0 or input[index - 1] != 0x80) return error.InvalidPadding;
            amount = input.len - index + 1;
        },
        .tbc => {
            const value = input[input.len - 1];
            if (value != 0x00 and value != 0xff) return error.InvalidPadding;
            amount = 0;
            while (amount < input.len and input[input.len - 1 - amount] == value) amount += 1;
        },
        .no_padding => unreachable,
    }
    return allocator.dupe(u8, input[0 .. input.len - amount]);
}

test "pkcs7 padding" {
    const allocator = std.testing.allocator;
    const padded = try add(allocator, "hello", 16, .pkcs7);
    defer allocator.free(padded);
    const plain = try remove(allocator, padded, 16, .pkcs7);
    defer allocator.free(plain);
    try std.testing.expectEqualSlices(u8, "hello", plain);
}

test "zero padding removes the zero suffix" {
    const allocator = std.testing.allocator;
    const padded = try add(allocator, "hello", 16, .zero);
    defer allocator.free(padded);
    const plain = try remove(allocator, padded, 16, .zero);
    defer allocator.free(plain);
    try std.testing.expectEqualSlices(u8, "hello", plain);
}
