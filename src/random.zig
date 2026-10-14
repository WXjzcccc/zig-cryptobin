const std = @import("std");

pub const Error = std.mem.Allocator.Error || std.Io.RandomSecureError;

/// Generates `length` cryptographically secure random bytes.
/// Ownership: the returned slice is allocated with `allocator`; the caller must release it with `allocator.free`.
pub fn bytes(allocator: std.mem.Allocator, length: usize) Error![]u8 {
    const output = try allocator.alloc(u8, length);
    errdefer allocator.free(output);
    var io_context = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_context.deinit();
    try io_context.io().randomSecure(output);
    return output;
}

/// Renders an SSH-style random-art fingerprint.
/// Ownership: the returned text is allocated with `allocator`; the caller must release it with `allocator.free`.
pub fn randomart(allocator: std.mem.Allocator, fingerprint: []const u8) std.mem.Allocator.Error![]u8 {
    const width = 17;
    const height = 9;
    const palette = " .o+=*BOX@%&#/^SE";
    var field: [width][height]u8 = @splat(@as([height]u8, @splat(0)));
    var x: usize = width / 2;
    var y: usize = height / 2;

    for (fingerprint) |byte| {
        var value = byte;
        for (0..4) |_| {
            if ((value & 1) != 0) x = @min(x + 1, width - 1) else x -|= 1;
            if ((value & 2) != 0) y = @min(y + 1, height - 1) else y -|= 1;
            if (field[x][y] < palette.len - 3) field[x][y] += 1;
            value >>= 2;
        }
    }
    field[width / 2][height / 2] = @intCast(palette.len - 2);
    field[x][y] = @intCast(palette.len - 1);

    const output = try allocator.alloc(u8, (width + 3) * (height + 2) - 1);
    var offset: usize = 0;
    output[offset] = '+';
    offset += 1;
    @memset(output[offset .. offset + width], '-');
    offset += width;
    output[offset] = '+';
    offset += 1;
    output[offset] = '\n';
    offset += 1;
    for (0..height) |row| {
        output[offset] = '|';
        offset += 1;
        for (0..width) |column| {
            output[offset] = palette[field[column][row]];
            offset += 1;
        }
        output[offset] = '|';
        offset += 1;
        output[offset] = '\n';
        offset += 1;
    }
    output[offset] = '+';
    offset += 1;
    @memset(output[offset .. offset + width], '-');
    offset += width;
    output[offset] = '+';
    return output;
}

test "randomart matches go-cryptobin layout" {
    const art = try randomart(std.testing.allocator, "test");
    defer std.testing.allocator.free(art);
    try std.testing.expectEqualStrings(
        "+-----------------+\n" ++
            "|            +.o E|\n" ++
            "|           o o . |\n" ++
            "|        . .      |\n" ++
            "|       . .       |\n" ++
            "|        S        |\n" ++
            "|                 |\n" ++
            "|                 |\n" ++
            "|                 |\n" ++
            "|                 |\n" ++
            "+-----------------+",
        art,
    );
}
