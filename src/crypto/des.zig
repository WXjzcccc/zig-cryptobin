const std = @import("std");

pub const block_length = 8;

const initial_permutation = [_]u8{
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
};
const final_permutation = [_]u8{
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25,
};
const key_permutation = [_]u8{
    57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7,  62, 54, 46, 38, 30, 22, 14, 6,  61, 53, 45, 37,
    29, 21, 13, 5,  28, 20, 12, 4,
};
const key_compression = [_]u8{
    14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,
    26, 8,  16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
};
const expansion_permutation = [_]u8{
    32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
};
const p_permutation = [_]u8{
    16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
    2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25,
};
const round_shifts = [_]u8{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
const sboxes = [8][64]u8{
    .{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
    .{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
    .{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
    .{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
    .{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
    .{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
    .{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
    .{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 },
};

fn permute(input: u64, table: []const u8, input_bits: u8) u64 {
    var output: u64 = 0;
    for (table) |position| {
        const shift: u6 = @intCast(input_bits - position);
        output = (output << 1) | ((input >> shift) & 1);
    }
    return output;
}

fn rotate28(value: u32, amount: u8) u32 {
    const shift: u5 = @intCast(amount);
    const reverse_shift: u5 = @intCast(28 - amount);
    return ((value << shift) | (value >> reverse_shift)) & 0x0fffffff;
}

fn roundKeys(key: [8]u8) [16]u64 {
    const key_value = std.mem.readInt(u64, &key, .big);
    const permuted = permute(key_value, &key_permutation, 64);
    var left: u32 = @intCast(permuted >> 28);
    var right: u32 = @intCast(permuted & 0x0fffffff);
    var keys: [16]u64 = undefined;
    for (round_shifts, 0..) |shift, index| {
        left = rotate28(left, shift);
        right = rotate28(right, shift);
        keys[index] = permute((@as(u64, left) << 28) | right, &key_compression, 56);
    }
    return keys;
}

fn feistel(right: u32, key: u64) u32 {
    const expanded = permute(right, &expansion_permutation, 32) ^ key;
    var substituted: u32 = 0;
    for (0..8) |index| {
        const shift: u6 = @intCast(42 - index * 6);
        const value: u8 = @intCast((expanded >> shift) & 0x3f);
        const row = ((value & 0x20) >> 4) | (value & 1);
        const column = (value >> 1) & 0x0f;
        substituted = (substituted << 4) | sboxes[index][@as(usize, row) * 16 + column];
    }
    return @intCast(permute(substituted, &p_permutation, 32));
}

fn apply(input: [8]u8, key: [8]u8, is_decrypt: bool) [8]u8 {
    const initial = permute(std.mem.readInt(u64, &input, .big), &initial_permutation, 64);
    var left: u32 = @intCast(initial >> 32);
    var right: u32 = @intCast(initial & 0xffffffff);
    const keys = roundKeys(key);
    for (0..16) |round| {
        const key_index = if (is_decrypt) 15 - round else round;
        const next = left ^ feistel(right, keys[key_index]);
        left = right;
        right = next;
    }
    const final = permute((@as(u64, right) << 32) | left, &final_permutation, 64);
    var output: [8]u8 = undefined;
    std.mem.writeInt(u64, &output, final, .big);
    return output;
}

pub fn encrypt(output: *[8]u8, input: [8]u8, key: [8]u8) void {
    output.* = apply(input, key, false);
}
pub fn decrypt(output: *[8]u8, input: [8]u8, key: [8]u8) void {
    output.* = apply(input, key, true);
}

pub fn encryptTriple(output: *[8]u8, input: [8]u8, first: [8]u8, second: [8]u8, third: [8]u8) void {
    var stage: [8]u8 = undefined;
    encrypt(&stage, input, first);
    decrypt(&stage, stage, second);
    encrypt(output, stage, third);
}

pub fn decryptTriple(output: *[8]u8, input: [8]u8, first: [8]u8, second: [8]u8, third: [8]u8) void {
    var stage: [8]u8 = undefined;
    decrypt(&stage, input, third);
    encrypt(&stage, stage, second);
    decrypt(output, stage, first);
}

test "FIPS 46-3 DES vector" {
    const key = [_]u8{ 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 };
    const plain = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    const expected = [_]u8{ 0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05 };
    var encrypted: [8]u8 = undefined;
    encrypt(&encrypted, plain, key);
    try std.testing.expectEqualSlices(u8, &expected, &encrypted);
    var decrypted: [8]u8 = undefined;
    decrypt(&decrypted, encrypted, key);
    try std.testing.expectEqualSlices(u8, &plain, &decrypted);
}
