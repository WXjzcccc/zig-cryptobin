const std = @import("std");

pub const Error = error{
    UnexpectedEnd,
    InvalidToken,
    InvalidInteger,
    InvalidByteString,
    UnsortedDictionary,
} || std.mem.Allocator.Error;

pub const Entry = struct {
    key: []u8,
    value: Value,
};

pub const Value = union(enum) {
    integer: i64,
    bytes: []u8,
    list: []Value,
    dict: []Entry,

    pub fn deinit(self: *Value, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .integer => {},
            .bytes => |value| allocator.free(value),
            .list => |values| {
                for (values) |*value| value.deinit(allocator);
                allocator.free(values);
            },
            .dict => |entries| {
                for (entries) |*entry| {
                    allocator.free(entry.key);
                    entry.value.deinit(allocator);
                }
                allocator.free(entries);
            },
        }
    }
};

fn appendUnsigned(writer: *std.ArrayList(u8), allocator: std.mem.Allocator, value: usize) !void {
    var buffer: [32]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{d}", .{value});
    try writer.appendSlice(allocator, text);
}

fn appendInteger(writer: *std.ArrayList(u8), allocator: std.mem.Allocator, value: i64) !void {
    var buffer: [32]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{d}", .{value});
    try writer.append(allocator, 'i');
    try writer.appendSlice(allocator, text);
    try writer.append(allocator, 'e');
}

fn appendBytes(writer: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try appendUnsigned(writer, allocator, value.len);
    try writer.append(allocator, ':');
    try writer.appendSlice(allocator, value);
}

fn entryLessThan(left: Entry, right: Entry) bool {
    return std.mem.order(u8, left.key, right.key) == .lt;
}

fn appendValue(writer: *std.ArrayList(u8), allocator: std.mem.Allocator, value: Value) !void {
    switch (value) {
        .integer => |number| try appendInteger(writer, allocator, number),
        .bytes => |bytes| try appendBytes(writer, allocator, bytes),
        .list => |values| {
            try writer.append(allocator, 'l');
            for (values) |item| try appendValue(writer, allocator, item);
            try writer.append(allocator, 'e');
        },
        .dict => |entries| {
            const sorted = try allocator.dupe(Entry, entries);
            defer allocator.free(sorted);
            var index: usize = 1;
            while (index < sorted.len) : (index += 1) {
                const current = sorted[index];
                var position = index;
                while (position > 0 and entryLessThan(current, sorted[position - 1])) : (position -= 1) {
                    sorted[position] = sorted[position - 1];
                }
                sorted[position] = current;
            }
            try writer.append(allocator, 'd');
            for (sorted) |entry| {
                try appendBytes(writer, allocator, entry.key);
                try appendValue(writer, allocator, entry.value);
            }
            try writer.append(allocator, 'e');
        },
    }
}

pub fn encode(allocator: std.mem.Allocator, value: Value) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try appendValue(&output, allocator, value);
    return output.toOwnedSlice(allocator);
}

const Parser = struct {
    allocator: std.mem.Allocator,
    input: []const u8,
    offset: usize = 0,

    fn peek(self: *const Parser) Error!u8 {
        if (self.offset >= self.input.len) return error.UnexpectedEnd;
        return self.input[self.offset];
    }

    fn consume(self: *Parser, token: u8) Error!void {
        if (try self.peek() != token) return error.InvalidToken;
        self.offset += 1;
    }

    fn parseBytes(self: *Parser) Error![]u8 {
        const start = self.offset;
        const separator = std.mem.indexOfScalarPos(u8, self.input, self.offset, ':') orelse return error.InvalidByteString;
        if (separator == start) return error.InvalidByteString;
        const length_text = self.input[start..separator];
        if ((length_text.len > 1 and length_text[0] == '0') or std.mem.indexOfScalar(u8, length_text, '-') != null) return error.InvalidByteString;
        const length = std.fmt.parseInt(usize, length_text, 10) catch return error.InvalidByteString;
        self.offset = separator + 1;
        if (length > self.input.len - self.offset) return error.UnexpectedEnd;
        const bytes = try self.allocator.dupe(u8, self.input[self.offset .. self.offset + length]);
        self.offset += length;
        return bytes;
    }

    fn parseInteger(self: *Parser) Error!Value {
        try self.consume('i');
        const start = self.offset;
        const end = std.mem.indexOfScalarPos(u8, self.input, self.offset, 'e') orelse return error.UnexpectedEnd;
        const text = self.input[start..end];
        if (text.len == 0 or std.mem.eql(u8, text, "-0") or (text.len > 1 and text[0] == '0') or (text.len > 2 and text[0] == '-' and text[1] == '0')) return error.InvalidInteger;
        const number = std.fmt.parseInt(i64, text, 10) catch return error.InvalidInteger;
        self.offset = end + 1;
        return .{ .integer = number };
    }

    fn parseList(self: *Parser) Error!Value {
        try self.consume('l');
        var values: std.ArrayList(Value) = .empty;
        errdefer {
            for (values.items) |*value| value.deinit(self.allocator);
            values.deinit(self.allocator);
        }
        while (try self.peek() != 'e') try values.append(self.allocator, try self.parseValue());
        self.offset += 1;
        return .{ .list = try values.toOwnedSlice(self.allocator) };
    }

    fn parseDict(self: *Parser) Error!Value {
        try self.consume('d');
        var entries: std.ArrayList(Entry) = .empty;
        errdefer {
            for (entries.items) |*entry| {
                self.allocator.free(entry.key);
                entry.value.deinit(self.allocator);
            }
            entries.deinit(self.allocator);
        }
        var previous_key: ?[]const u8 = null;
        while (try self.peek() != 'e') {
            const key = try self.parseBytes();
            errdefer self.allocator.free(key);
            if (previous_key) |previous| if (std.mem.order(u8, previous, key) != .lt) return error.UnsortedDictionary;
            const value = try self.parseValue();
            errdefer {
                var owned_value = value;
                owned_value.deinit(self.allocator);
            }
            try entries.append(self.allocator, .{ .key = key, .value = value });
            previous_key = key;
        }
        self.offset += 1;
        return .{ .dict = try entries.toOwnedSlice(self.allocator) };
    }

    fn parseValue(self: *Parser) Error!Value {
        return switch (try self.peek()) {
            'i' => self.parseInteger(),
            'l' => self.parseList(),
            'd' => self.parseDict(),
            '0'...'9' => .{ .bytes = try self.parseBytes() },
            else => error.InvalidToken,
        };
    }
};

pub fn decode(allocator: std.mem.Allocator, input: []const u8) Error!Value {
    var parser = Parser{ .allocator = allocator, .input = input };
    var value = try parser.parseValue();
    errdefer value.deinit(allocator);
    if (parser.offset != input.len) return error.InvalidToken;
    return value;
}

test "rejects a non-canonical dictionary order" {
    try std.testing.expectError(error.UnsortedDictionary, decode(std.testing.allocator, "d3:fooi1e3:bari2ee"));
}

test "canonical bencode dictionary round trip" {
    const allocator = std.testing.allocator;
    const first_key = try allocator.dupe(u8, "foo");
    defer allocator.free(first_key);
    const second_key = try allocator.dupe(u8, "bar");
    defer allocator.free(second_key);
    const spam = try allocator.dupe(u8, "spam");
    defer allocator.free(spam);
    const entries = [_]Entry{
        .{ .key = first_key, .value = .{ .integer = 42 } },
        .{ .key = second_key, .value = .{ .bytes = spam } },
    };
    const encoded = try encode(allocator, .{ .dict = @constCast(entries[0..]) });
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("d3:bar4:spam3:fooi42ee", encoded);

    var decoded = try decode(allocator, encoded);
    defer decoded.deinit(allocator);
    switch (decoded) {
        .dict => |items| {
            try std.testing.expectEqual(@as(usize, 2), items.len);
            try std.testing.expectEqualStrings("bar", items[0].key);
            try std.testing.expectEqualStrings("spam", items[0].value.bytes);
            try std.testing.expectEqualStrings("foo", items[1].key);
            try std.testing.expectEqual(@as(i64, 42), items[1].value.integer);
        },
        else => return error.TestExpectedEqual,
    }
}
