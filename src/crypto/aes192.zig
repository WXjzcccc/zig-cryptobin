const std = @import("std");

pub const block_length = 16;
pub const key_length = 24;
const rounds = 12;
const round_key_length = block_length * (rounds + 1);

fn gmul(left: u8, right: u8) u8 {
    var a = left;
    var b = right;
    var result: u8 = 0;
    while (b != 0) : (b >>= 1) {
        if ((b & 1) != 0) result ^= a;
        a = if ((a & 0x80) != 0) (a << 1) ^ 0x1b else a << 1;
    }
    return result;
}

fn inverse(value: u8) u8 {
    if (value == 0) return 0;
    var result: u8 = 1;
    var base = value;
    var exponent: u8 = 254;
    while (exponent != 0) : (exponent >>= 1) {
        if ((exponent & 1) != 0) result = gmul(result, base);
        base = gmul(base, base);
    }
    return result;
}

const sbox_table = [256]u8{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

fn sbox(value: u8) u8 {
    return sbox_table[value];
}

fn inverseSbox(value: u8) u8 {
    var candidate: u16 = 0;
    while (candidate <= 0xff) : (candidate += 1) {
        const byte: u8 = @intCast(candidate);
        if (sbox(byte) == value) return byte;
    }
    unreachable;
}

fn rcon(index: usize) u8 {
    var value: u8 = 1;
    for (1..index) |_| value = gmul(value, 2);
    return value;
}

fn expandKey(key: [key_length]u8) [round_key_length]u8 {
    var expanded: [round_key_length]u8 = undefined;
    @memcpy(expanded[0..key_length], &key);
    var word: usize = 6;
    while (word < 4 * (rounds + 1)) : (word += 1) {
        var temp: [4]u8 = undefined;
        @memcpy(&temp, expanded[(word - 1) * 4 .. word * 4]);
        if (word % 6 == 0) {
            const previous = temp;
            temp = .{ sbox(previous[1]), sbox(previous[2]), sbox(previous[3]), sbox(previous[0]) };
            temp[0] ^= rcon(word / 6);
        }
        for (0..4) |index| expanded[word * 4 + index] = expanded[(word - 6) * 4 + index] ^ temp[index];
    }
    return expanded;
}

fn addRoundKey(state: *[block_length]u8, round_keys: []const u8, round: usize) void {
    for (state, round_keys[round * block_length ..][0..block_length]) |*value, key_byte| value.* ^= key_byte;
}

fn substitute(state: *[block_length]u8, inverse_substitution: bool) void {
    for (state) |*value| value.* = if (inverse_substitution) inverseSbox(value.*) else sbox(value.*);
}

fn shiftRows(state: *[block_length]u8, reverse: bool) void {
    for (1..4) |row| {
        var copy: [4]u8 = undefined;
        for (0..4) |column| copy[column] = state[column * 4 + row];
        for (0..4) |column| {
            const offset = if (reverse) (column + 4 - row) % 4 else (column + row) % 4;
            state[column * 4 + row] = copy[offset];
        }
    }
}

fn mixColumns(state: *[block_length]u8, inverse_mix: bool) void {
    for (0..4) |column| {
        const offset = column * 4;
        const a = state[offset];
        const b = state[offset + 1];
        const c = state[offset + 2];
        const d = state[offset + 3];
        if (inverse_mix) {
            state[offset] = gmul(a, 14) ^ gmul(b, 11) ^ gmul(c, 13) ^ gmul(d, 9);
            state[offset + 1] = gmul(a, 9) ^ gmul(b, 14) ^ gmul(c, 11) ^ gmul(d, 13);
            state[offset + 2] = gmul(a, 13) ^ gmul(b, 9) ^ gmul(c, 14) ^ gmul(d, 11);
            state[offset + 3] = gmul(a, 11) ^ gmul(b, 13) ^ gmul(c, 9) ^ gmul(d, 14);
        } else {
            state[offset] = gmul(a, 2) ^ gmul(b, 3) ^ c ^ d;
            state[offset + 1] = a ^ gmul(b, 2) ^ gmul(c, 3) ^ d;
            state[offset + 2] = a ^ b ^ gmul(c, 2) ^ gmul(d, 3);
            state[offset + 3] = gmul(a, 3) ^ b ^ c ^ gmul(d, 2);
        }
    }
}

pub fn encrypt(output: *[block_length]u8, input: [block_length]u8, key: [key_length]u8) void {
    const round_keys = expandKey(key);
    var state = input;
    addRoundKey(&state, &round_keys, 0);
    for (1..rounds) |round| {
        substitute(&state, false);
        shiftRows(&state, false);
        mixColumns(&state, false);
        addRoundKey(&state, &round_keys, round);
    }
    substitute(&state, false);
    shiftRows(&state, false);
    addRoundKey(&state, &round_keys, rounds);
    output.* = state;
}

pub fn decrypt(output: *[block_length]u8, input: [block_length]u8, key: [key_length]u8) void {
    const round_keys = expandKey(key);
    var state = input;
    addRoundKey(&state, &round_keys, rounds);
    var round: usize = rounds - 1;
    while (round > 0) : (round -= 1) {
        shiftRows(&state, true);
        substitute(&state, true);
        addRoundKey(&state, &round_keys, round);
        mixColumns(&state, true);
    }
    shiftRows(&state, true);
    substitute(&state, true);
    addRoundKey(&state, &round_keys, 0);
    output.* = state;
}

test "FIPS-197 AES-192 vector" {
    try std.testing.expectEqual(@as(u8, 0xed), sbox(0x53));
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    const plain = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const expected = [_]u8{ 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
    const expanded = expandKey(key);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x58, 0x46, 0xf2, 0xf9 }, expanded[24..28]);
    var encrypted: [16]u8 = undefined;
    encrypt(&encrypted, plain, key);
    try std.testing.expectEqualSlices(u8, &expected, &encrypted);
    var decrypted: [16]u8 = undefined;
    decrypt(&decrypted, encrypted, key);
    try std.testing.expectEqualSlices(u8, &plain, &decrypted);
}
