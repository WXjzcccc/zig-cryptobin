const std = @import("std");
const cipher = @import("cipher.zig");
const encoding = @import("encoding.zig");
const modes = @import("modes.zig");
const padding = @import("padding.zig");
const chacha20 = @import("crypto/chacha20.zig");
const rc4 = @import("crypto/rc4.zig");

pub const Error = error{
    InvalidKeyLength,
    InvalidIvLength,
    InvalidBlockLength,
    InvalidPadding,
    InvalidBase64,
    InvalidHex,
    AuthenticationFailed,
    UnsupportedCcmParameters,
} || std.mem.Allocator.Error || cipher.Error || modes.Error || padding.Error || encoding.Error || std.crypto.errors.AuthenticationError;

pub const Cryptobin = struct {
    allocator: std.mem.Allocator,
    data: []u8,
    key: []u8,
    iv: []u8,
    parsed_data: []u8,
    algorithm: cipher.Algorithm,
    mode: modes.Kind,
    padding_kind: padding.Kind,
    additional_data: []u8,
    counter: u32,
    tea_rounds: u32,
    use_gcm: bool,
    use_ccm: bool,
    ccm_tag_length: u8,

    /// Initializes an empty Cryptobin using allocator for all owned buffers.
    /// Ownership: the returned struct is an inline value; call its deinit method to release buffers it later owns.
    pub fn init(allocator: std.mem.Allocator) Cryptobin {
        return .{
            .allocator = allocator,
            .data = &[_]u8{},
            .key = &[_]u8{},
            .iv = &[_]u8{},
            .parsed_data = &[_]u8{},
            .algorithm = .aes,
            .mode = .ecb,
            .padding_kind = .no_padding,
            .additional_data = &[_]u8{},
            .counter = 1,
            .tea_rounds = 64,
            .use_gcm = false,
            .use_ccm = false,
            .ccm_tag_length = 16,
        };
    }

    /// Releases the input, key, IV, associated data, parsed data, and any other owned buffers.
    /// Ownership: call this exactly once for each initialized Cryptobin, using the allocator supplied at initialization.
    pub fn deinit(self: *Cryptobin) void {
        self.free(&self.data);
        self.free(&self.key);
        self.free(&self.iv);
        self.free(&self.parsed_data);
        self.free(&self.additional_data);
    }

    fn free(self: *Cryptobin, value: *[]u8) void {
        if (value.len > 0) self.allocator.free(value.*);
        value.* = &[_]u8{};
    }

    fn replace(self: *Cryptobin, destination: *[]u8, source: []const u8) !void {
        const next = try self.allocator.dupe(u8, source);
        self.free(destination);
        destination.* = next;
    }

    fn replaceOwned(self: *Cryptobin, destination: *[]u8, source: []u8) void {
        self.free(destination);
        destination.* = source;
    }

    fn disableAead(self: *Cryptobin) void {
        self.use_gcm = false;
        self.use_ccm = false;
    }

    /// Copies value into the input data and returns self for fluent configuration.
    /// Ownership: no new return value is allocated; release the Cryptobin with deinit when finished.
    pub fn FromBytes(self: *Cryptobin, value: []const u8) !*Cryptobin {
        try self.replace(&self.data, value);
        return self;
    }

    /// Copies a string into the input data and returns self for fluent configuration.
    /// Ownership: no new return value is allocated; release the Cryptobin with deinit when finished.
    pub fn FromString(self: *Cryptobin, value: []const u8) !*Cryptobin {
        return self.FromBytes(value);
    }

    /// Decodes a Base64 string into the input data and returns self.
    /// Ownership: decoded data becomes owned by self; release it with deinit. The returned pointer is borrowed.
    pub fn FromBase64String(self: *Cryptobin, value: []const u8) !*Cryptobin {
        const decoded = try encoding.base64Decode(self.allocator, value);
        self.replaceOwned(&self.data, decoded);
        return self;
    }

    /// Decodes a hexadecimal string into the input data and returns self.
    /// Ownership: decoded data becomes owned by self; release it with deinit. The returned pointer is borrowed.
    pub fn FromHexString(self: *Cryptobin, value: []const u8) !*Cryptobin {
        const decoded = try encoding.hexDecode(self.allocator, value);
        self.replaceOwned(&self.data, decoded);
        return self;
    }

    /// Copies value into the cipher key and returns self.
    /// Ownership: the key copy is owned by self and released by deinit; the returned pointer is borrowed.
    pub fn SetKey(self: *Cryptobin, value: []const u8) !*Cryptobin {
        try self.replace(&self.key, value);
        return self;
    }

    /// Alias for SetKey for fluent configuration.
    /// Ownership: the key copy is released by deinit; the returned pointer is borrowed.
    pub fn WithKey(self: *Cryptobin, value: []const u8) !*Cryptobin {
        return self.SetKey(value);
    }

    /// Copies value into the initialization vector and returns self.
    /// Ownership: the IV copy is owned by self and released by deinit; the returned pointer is borrowed.
    pub fn SetIv(self: *Cryptobin, value: []const u8) !*Cryptobin {
        try self.replace(&self.iv, value);
        return self;
    }

    /// Alias for SetIv for fluent configuration.
    /// Ownership: the IV copy is released by deinit; the returned pointer is borrowed.
    pub fn WithIv(self: *Cryptobin, value: []const u8) !*Cryptobin {
        return self.SetIv(value);
    }

    /// Copies associated authenticated data and returns self.
    /// Ownership: the copy is owned by self and released by deinit; the returned pointer is borrowed.
    pub fn SetAdditional(self: *Cryptobin, value: []const u8) !*Cryptobin {
        try self.replace(&self.additional_data, value);
        return self;
    }

    /// Selects AES and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn Aes(self: *Cryptobin) *Cryptobin {
        self.algorithm = .aes;
        return self;
    }

    /// Selects DES and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn Des(self: *Cryptobin) *Cryptobin {
        self.algorithm = .des;
        self.disableAead();
        return self;
    }

    /// Selects two-key TripleDES and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn TwoDes(self: *Cryptobin) *Cryptobin {
        self.algorithm = .two_des;
        self.disableAead();
        return self;
    }

    /// Selects three-key TripleDES and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn TripleDes(self: *Cryptobin) *Cryptobin {
        self.algorithm = .triple_des;
        self.disableAead();
        return self;
    }

    /// Selects RC4 and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn RC4(self: *Cryptobin) *Cryptobin {
        self.algorithm = .rc4;
        self.disableAead();
        return self;
    }

    /// Selects RC4 with an MD5-derived key and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn RC4MD5(self: *Cryptobin) *Cryptobin {
        self.algorithm = .rc4_md5;
        self.disableAead();
        return self;
    }

    /// Selects TEA and optionally sets its round count.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn Tea(self: *Cryptobin, rounds: ?u32) *Cryptobin {
        self.algorithm = .tea;
        self.disableAead();
        if (rounds) |value| self.tea_rounds = value else self.tea_rounds = 64;
        return self;
    }

    /// Selects XTEA and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn Xtea(self: *Cryptobin) *Cryptobin {
        self.algorithm = .xtea;
        self.disableAead();
        return self;
    }

    /// Selects SM4 and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn SM4(self: *Cryptobin) *Cryptobin {
        self.algorithm = .sm4;
        self.disableAead();
        return self;
    }

    /// Selects ChaCha20 and sets its initial block counter.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn Chacha20(self: *Cryptobin, counter: u32) *Cryptobin {
        self.algorithm = .chacha20;
        self.disableAead();
        self.counter = counter;
        return self;
    }

    /// Selects ChaCha20-Poly1305 and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn Chacha20poly1305(self: *Cryptobin) *Cryptobin {
        self.algorithm = .chacha20_poly1305;
        self.disableAead();
        return self;
    }

    /// Selects XChaCha20-Poly1305 and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn Chacha20poly1305X(self: *Cryptobin) *Cryptobin {
        self.algorithm = .xchacha20_poly1305;
        self.disableAead();
        return self;
    }

    /// Selects ECB mode and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn ECB(self: *Cryptobin) *Cryptobin {
        self.mode = .ecb;
        self.disableAead();
        return self;
    }
    /// Selects CBC mode and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn CBC(self: *Cryptobin) *Cryptobin {
        self.mode = .cbc;
        self.disableAead();
        return self;
    }
    /// Selects PCBC mode and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn PCBC(self: *Cryptobin) *Cryptobin {
        self.mode = .pcbc;
        self.disableAead();
        return self;
    }
    /// Selects CFB mode and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn CFB(self: *Cryptobin) *Cryptobin {
        self.mode = .cfb;
        self.disableAead();
        return self;
    }
    /// Selects OFB mode and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn OFB(self: *Cryptobin) *Cryptobin {
        self.mode = .ofb;
        self.disableAead();
        return self;
    }
    /// Selects CTR mode and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn CTR(self: *Cryptobin) *Cryptobin {
        self.mode = .ctr;
        self.disableAead();
        return self;
    }
    /// Selects AES-GCM and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn GCM(self: *Cryptobin) *Cryptobin {
        self.algorithm = .aes;
        self.use_gcm = true;
        self.use_ccm = false;
        return self;
    }

    /// Selects AES-CCM with a 16-byte tag and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn CCM(self: *Cryptobin) *Cryptobin {
        self.algorithm = .aes;
        self.disableAead();
        self.use_ccm = true;
        self.ccm_tag_length = 16;
        return self;
    }

    /// Selects AES-CCM and applies the requested nonce-size configuration.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn CCMWithNonceSize(self: *Cryptobin, nonce_size: usize) *Cryptobin {
        _ = self.CCM();
        if (nonce_size != 13) self.ccm_tag_length = 0;
        return self;
    }

    /// Selects AES-CCM and sets the requested authentication tag size.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn CCMWithTagSize(self: *Cryptobin, tag_size: usize) *Cryptobin {
        _ = self.CCM();
        self.ccm_tag_length = @intCast(tag_size);
        return self;
    }

    /// Selects AES-CCM and sets both nonce-size and tag-size configuration.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn CCMWithNonceAndTagSize(self: *Cryptobin, nonce_size: usize, tag_size: usize) *Cryptobin {
        self.CCMWithNonceSize(nonce_size);
        self.ccm_tag_length = @intCast(tag_size);
        return self;
    }

    /// Selects no padding and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn NoPadding(self: *Cryptobin) *Cryptobin {
        self.padding_kind = .no_padding;
        return self;
    }
    /// Selects zero padding and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn ZeroPadding(self: *Cryptobin) *Cryptobin {
        self.padding_kind = .zero;
        return self;
    }
    /// Selects PKCS5 padding and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn PKCS5Padding(self: *Cryptobin) *Cryptobin {
        self.padding_kind = .pkcs5;
        return self;
    }
    /// Selects PKCS7 padding and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn PKCS7Padding(self: *Cryptobin) *Cryptobin {
        self.padding_kind = .pkcs7;
        return self;
    }
    /// Selects X9.23 padding and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn X923Padding(self: *Cryptobin) *Cryptobin {
        self.padding_kind = .x923;
        return self;
    }
    /// Selects ISO 10126 padding and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn ISO10126Padding(self: *Cryptobin) *Cryptobin {
        self.padding_kind = .iso10126;
        return self;
    }
    /// Selects ISO 7816-4 padding and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn ISO7816_4Padding(self: *Cryptobin) *Cryptobin {
        self.padding_kind = .iso7816_4;
        return self;
    }
    /// Selects ISO 9797-1 padding and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn ISO97971Padding(self: *Cryptobin) *Cryptobin {
        self.padding_kind = .iso97971;
        return self;
    }
    /// Selects PBOC2 padding and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn PBOC2Padding(self: *Cryptobin) *Cryptobin {
        self.padding_kind = .pboc2;
        return self;
    }
    /// Selects TBC padding and returns self.
    /// Ownership: no allocation is performed; release the Cryptobin with deinit.
    pub fn TBCPadding(self: *Cryptobin) *Cryptobin {
        self.padding_kind = .tbc;
        return self;
    }

    /// Copies the current input into the parsed-data buffer without decoding or transforming it.
    /// Ownership: the copy is owned by self and released by deinit; the returned pointer is borrowed.
    pub fn NoParse(self: *Cryptobin) !*Cryptobin {
        try self.replace(&self.parsed_data, self.data);
        return self;
    }

    fn encryptAead(self: *Cryptobin) ![]u8 {
        const nonce_len: usize = if (self.algorithm == .xchacha20_poly1305) 24 else 12;
        if (self.iv.len != nonce_len) return error.InvalidIvLength;
        if (self.key.len != 32) return error.InvalidKeyLength;
        const output = try self.allocator.alloc(u8, self.data.len + 16);
        errdefer self.allocator.free(output);
        const message = output[0..self.data.len];
        const tag = output[self.data.len..][0..16];
        var key: [32]u8 = undefined;
        @memcpy(&key, self.key);
        if (self.algorithm == .chacha20_poly1305) {
            var nonce: [12]u8 = undefined;
            @memcpy(&nonce, self.iv);
            const tag_array: *[16]u8 = @ptrCast(tag.ptr);
            std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(message, tag_array, self.data, self.additional_data, nonce, key);
        } else {
            var nonce: [24]u8 = undefined;
            @memcpy(&nonce, self.iv);
            const tag_array: *[16]u8 = @ptrCast(tag.ptr);
            std.crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(message, tag_array, self.data, self.additional_data, nonce, key);
        }
        return output;
    }

    fn decryptAead(self: *Cryptobin) ![]u8 {
        const nonce_len: usize = if (self.algorithm == .xchacha20_poly1305) 24 else 12;
        if (self.iv.len != nonce_len) return error.InvalidIvLength;
        if (self.key.len != 32) return error.InvalidKeyLength;
        if (self.data.len < 16) return error.AuthenticationFailed;
        const message_len = self.data.len - 16;
        const output = try self.allocator.alloc(u8, message_len);
        errdefer self.allocator.free(output);
        var key: [32]u8 = undefined;
        @memcpy(&key, self.key);
        var tag: [16]u8 = undefined;
        @memcpy(&tag, self.data[message_len..]);
        if (self.algorithm == .chacha20_poly1305) {
            var nonce: [12]u8 = undefined;
            @memcpy(&nonce, self.iv);
            std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(output, self.data[0..message_len], tag, self.additional_data, nonce, key) catch return error.AuthenticationFailed;
        } else {
            var nonce: [24]u8 = undefined;
            @memcpy(&nonce, self.iv);
            std.crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(output, self.data[0..message_len], tag, self.additional_data, nonce, key) catch return error.AuthenticationFailed;
        }
        return output;
    }

    fn encryptGcm(self: *Cryptobin) ![]u8 {
        if (self.iv.len != 12) return error.InvalidIvLength;
        if (self.key.len != 16 and self.key.len != 32) return error.InvalidKeyLength;
        const output = try self.allocator.alloc(u8, self.data.len + 16);
        errdefer self.allocator.free(output);
        const message = output[0..self.data.len];
        const tag = output[self.data.len..][0..16];
        var nonce: [12]u8 = undefined;
        const tag_array: *[16]u8 = @ptrCast(tag.ptr);
        @memcpy(&nonce, self.iv);
        if (self.key.len == 16) {
            var key: [16]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(message, tag_array, self.data, self.additional_data, nonce, key);
        } else {
            var key: [32]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(message, tag_array, self.data, self.additional_data, nonce, key);
        }
        return output;
    }

    fn decryptGcm(self: *Cryptobin) ![]u8 {
        if (self.iv.len != 12) return error.InvalidIvLength;
        if (self.data.len < 16) return error.AuthenticationFailed;
        if (self.key.len != 16 and self.key.len != 32) return error.InvalidKeyLength;
        const message_len = self.data.len - 16;
        const output = try self.allocator.alloc(u8, message_len);
        errdefer self.allocator.free(output);
        var nonce: [12]u8 = undefined;
        var tag: [16]u8 = undefined;
        @memcpy(&nonce, self.iv);
        @memcpy(&tag, self.data[message_len..]);
        if (self.key.len == 16) {
            var key: [16]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(output, self.data[0..message_len], tag, self.additional_data, nonce, key) catch return error.AuthenticationFailed;
        } else {
            var key: [32]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(output, self.data[0..message_len], tag, self.additional_data, nonce, key) catch return error.AuthenticationFailed;
        }
        return output;
    }

    fn encryptCcm(self: *Cryptobin) ![]u8 {
        if (self.iv.len != 13) return error.InvalidIvLength;
        if (self.key.len != 16 and self.key.len != 32) return error.InvalidKeyLength;
        if (self.ccm_tag_length != 8 and self.ccm_tag_length != 16) return error.UnsupportedCcmParameters;
        const output = try self.allocator.alloc(u8, self.data.len + self.ccm_tag_length);
        errdefer self.allocator.free(output);
        const message = output[0..self.data.len];
        var nonce: [13]u8 = undefined;
        @memcpy(&nonce, self.iv);
        if (self.ccm_tag_length == 8 and self.key.len == 16) {
            const tag_array: *[8]u8 = @ptrCast(output[self.data.len..].ptr);
            var key: [16]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_ccm.Aes128Ccm8.encrypt(message, tag_array, self.data, self.additional_data, nonce, key);
        } else if (self.ccm_tag_length == 8) {
            const tag_array: *[8]u8 = @ptrCast(output[self.data.len..].ptr);
            var key: [32]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_ccm.Aes256Ccm8.encrypt(message, tag_array, self.data, self.additional_data, nonce, key);
        } else if (self.key.len == 16) {
            const tag_array: *[16]u8 = @ptrCast(output[self.data.len..].ptr);
            var key: [16]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_ccm.Aes128Ccm16.encrypt(message, tag_array, self.data, self.additional_data, nonce, key);
        } else {
            const tag_array: *[16]u8 = @ptrCast(output[self.data.len..].ptr);
            var key: [32]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_ccm.Aes256Ccm16.encrypt(message, tag_array, self.data, self.additional_data, nonce, key);
        }
        return output;
    }

    fn decryptCcm(self: *Cryptobin) ![]u8 {
        if (self.iv.len != 13) return error.InvalidIvLength;
        if (self.key.len != 16 and self.key.len != 32) return error.InvalidKeyLength;
        if (self.ccm_tag_length != 8 and self.ccm_tag_length != 16) return error.UnsupportedCcmParameters;
        if (self.data.len < self.ccm_tag_length) return error.AuthenticationFailed;
        const message_len = self.data.len - self.ccm_tag_length;
        const output = try self.allocator.alloc(u8, message_len);
        errdefer self.allocator.free(output);
        var nonce: [13]u8 = undefined;
        @memcpy(&nonce, self.iv);
        if (self.ccm_tag_length == 8 and self.key.len == 16) {
            var tag: [8]u8 = undefined;
            @memcpy(&tag, self.data[message_len..]);
            var key: [16]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_ccm.Aes128Ccm8.decrypt(output, self.data[0..message_len], tag, self.additional_data, nonce, key) catch return error.AuthenticationFailed;
        } else if (self.ccm_tag_length == 8) {
            var tag: [8]u8 = undefined;
            @memcpy(&tag, self.data[message_len..]);
            var key: [32]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_ccm.Aes256Ccm8.decrypt(output, self.data[0..message_len], tag, self.additional_data, nonce, key) catch return error.AuthenticationFailed;
        } else if (self.key.len == 16) {
            var tag: [16]u8 = undefined;
            @memcpy(&tag, self.data[message_len..]);
            var key: [16]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_ccm.Aes128Ccm16.decrypt(output, self.data[0..message_len], tag, self.additional_data, nonce, key) catch return error.AuthenticationFailed;
        } else {
            var tag: [16]u8 = undefined;
            @memcpy(&tag, self.data[message_len..]);
            var key: [32]u8 = undefined;
            @memcpy(&key, self.key);
            std.crypto.aead.aes_ccm.Aes256Ccm16.decrypt(output, self.data[0..message_len], tag, self.additional_data, nonce, key) catch return error.AuthenticationFailed;
        }
        return output;
    }

    fn streamChaCha(self: *Cryptobin) ![]u8 {
        try cipher.validateKey(.chacha20, self.key);
        if (self.iv.len != 12) return error.InvalidIvLength;
        const output = try self.allocator.alloc(u8, self.data.len);
        var key: [32]u8 = undefined;
        var nonce: [12]u8 = undefined;
        @memcpy(&key, self.key);
        @memcpy(&nonce, self.iv);
        try chacha20.xor(output, self.data, self.counter, key, nonce);
        return output;
    }

    fn streamRc4(self: *Cryptobin) ![]u8 {
        const output = try self.allocator.alloc(u8, self.data.len);
        errdefer self.allocator.free(output);
        if (self.algorithm == .rc4) {
            try rc4.xor(output, self.data, self.key);
        } else {
            var derived_key: [std.crypto.hash.Md5.digest_length]u8 = undefined;
            var hasher = std.crypto.hash.Md5.init(.{});
            hasher.update(self.key);
            hasher.update(self.iv);
            hasher.final(&derived_key);
            try rc4.xor(output, self.data, &derived_key);
        }
        return output;
    }

    /// Encrypts the current input according to the selected algorithm, mode, and padding.
    /// Ownership: the encrypted result becomes owned by self and is released by deinit; the returned pointer is borrowed.
    pub fn Encrypt(self: *Cryptobin) !*Cryptobin {
        var output: []u8 = undefined;
        if (self.algorithm == .chacha20_poly1305 or self.algorithm == .xchacha20_poly1305) {
            output = try self.encryptAead();
        } else if (self.use_gcm) {
            output = try self.encryptGcm();
        } else if (self.use_ccm) {
            output = try self.encryptCcm();
        } else if (self.algorithm == .chacha20) {
            output = try self.streamChaCha();
        } else if (self.algorithm == .rc4 or self.algorithm == .rc4_md5) {
            output = try self.streamRc4();
        } else {
            const padded = try padding.add(self.allocator, self.data, cipher.blockLength(self.algorithm), self.padding_kind);
            defer self.allocator.free(padded);
            output = try modes.apply(self.allocator, self.algorithm, self.key, padded, self.iv, self.mode, true, self.tea_rounds);
        }
        self.replaceOwned(&self.parsed_data, output);
        return self;
    }

    /// Decrypts the current input according to the selected algorithm, mode, and padding.
    /// Ownership: the decrypted result becomes owned by self and is released by deinit; the returned pointer is borrowed.
    pub fn Decrypt(self: *Cryptobin) !*Cryptobin {
        var output: []u8 = undefined;
        if (self.algorithm == .chacha20_poly1305 or self.algorithm == .xchacha20_poly1305) {
            output = try self.decryptAead();
        } else if (self.use_gcm) {
            output = try self.decryptGcm();
        } else if (self.use_ccm) {
            output = try self.decryptCcm();
        } else if (self.algorithm == .chacha20) {
            output = try self.streamChaCha();
        } else if (self.algorithm == .rc4 or self.algorithm == .rc4_md5) {
            output = try self.streamRc4();
        } else {
            const decrypted = try modes.apply(self.allocator, self.algorithm, self.key, self.data, self.iv, self.mode, false, self.tea_rounds);
            defer self.allocator.free(decrypted);
            output = try padding.remove(self.allocator, decrypted, cipher.blockLength(self.algorithm), self.padding_kind);
        }
        self.replaceOwned(&self.parsed_data, output);
        return self;
    }

    /// Returns the current parsed data without copying it.
    /// Ownership: the returned slice is borrowed from self and must not be freed; it is valid until self changes or is deinitialized.
    pub fn ToBytes(self: *const Cryptobin) []const u8 {
        return self.parsed_data;
    }
    /// Returns the current parsed data as a borrowed byte string without copying it.
    /// Ownership: the returned slice is borrowed from self and must not be freed; it is valid until self changes or is deinitialized.
    pub fn ToString(self: *const Cryptobin) []const u8 {
        return self.parsed_data;
    }
    /// Encodes the current parsed data as Base64.
    /// Ownership: the returned slice is newly allocated with self's allocator; the caller must release it with self.allocator.free.
    pub fn ToBase64String(self: *const Cryptobin) ![]u8 {
        return encoding.base64Encode(self.allocator, self.parsed_data);
    }
    /// Encodes the current parsed data as lower-case hexadecimal text.
    /// Ownership: the returned slice is newly allocated with self's allocator; the caller must release it with self.allocator.free.
    pub fn ToHexString(self: *const Cryptobin) ![]u8 {
        return encoding.hexEncode(self.allocator, self.parsed_data);
    }
};

/// Creates an empty Cryptobin value using allocator.
/// Ownership: the returned struct is an inline value; call deinit to release buffers it later owns.
pub fn New(allocator: std.mem.Allocator) Cryptobin {
    return Cryptobin.init(allocator);
}

/// Creates a Cryptobin whose input is a copy of value.
/// Ownership: the returned value owns its internal buffers; call result.deinit() when finished.
pub fn FromBytes(allocator: std.mem.Allocator, value: []const u8) !Cryptobin {
    var result = Cryptobin.init(allocator);
    errdefer result.deinit();
    _ = try result.FromBytes(value);
    return result;
}

/// Creates a Cryptobin from a byte string.
/// Ownership: the returned value owns its internal buffers; call result.deinit() when finished.
pub fn FromString(allocator: std.mem.Allocator, value: []const u8) !Cryptobin {
    return FromBytes(allocator, value);
}

/// Creates a Cryptobin by decoding a Base64 string.
/// Ownership: the returned value owns its internal buffers; call result.deinit() when finished.
pub fn FromBase64String(allocator: std.mem.Allocator, value: []const u8) !Cryptobin {
    var result = Cryptobin.init(allocator);
    errdefer result.deinit();
    _ = try result.FromBase64String(value);
    return result;
}

/// Creates a Cryptobin by decoding a hexadecimal string.
/// Ownership: the returned value owns its internal buffers; call result.deinit() when finished.
pub fn FromHexString(allocator: std.mem.Allocator, value: []const u8) !Cryptobin {
    var result = Cryptobin.init(allocator);
    errdefer result.deinit();
    _ = try result.FromHexString(value);
    return result;
}

test "fluent AES CBC compatibility" {
    const allocator = std.testing.allocator;
    var crypt = try FromString(allocator, "useData");
    defer crypt.deinit();
    _ = try crypt.SetKey("dfertf12dfertf12");
    _ = try crypt.SetIv("1234567890abcdef");
    _ = try crypt.Aes().CBC().PKCS7Padding().Encrypt();
    const encoded = try crypt.ToBase64String();
    defer allocator.free(encoded);

    var decoded = try FromBase64String(allocator, encoded);
    defer decoded.deinit();
    _ = try decoded.SetKey("dfertf12dfertf12");
    _ = try decoded.SetIv("1234567890abcdef");
    _ = try decoded.Aes().CBC().PKCS7Padding().Decrypt();
    try std.testing.expectEqualSlices(u8, "useData", decoded.ToString());
}

test "go-cryptobin default AES ECB compatibility" {
    const allocator = std.testing.allocator;
    var crypt = try FromString(allocator, "useData5useData5");
    defer crypt.deinit();
    _ = try crypt.SetKey("dfertf12dfertf12");
    _ = try crypt.Encrypt();
    const encoded = try crypt.ToBase64String();
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("eZf7c3fcwKlmrqogiEHbJg==", encoded);

    var decrypted = try FromBase64String(allocator, "eZf7c3fcwKlmrqogiEHbJg==");
    defer decrypted.deinit();
    _ = try decrypted.SetKey("dfertf12dfertf12");
    _ = try decrypted.Decrypt();
    try std.testing.expectEqualSlices(u8, "useData5useData5", decrypted.ToBytes());
}

test "TripleDES CBC interoperates with NIST vector" {
    const allocator = std.testing.allocator;
    const key = [_]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
    };
    const iv = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    const plain = [_]u8{ 0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74 };
    const expected = [_]u8{ 0xf3, 0xc0, 0xff, 0x02, 0x6c, 0x02, 0x30, 0x89 };
    var crypt = try FromBytes(allocator, &plain);
    defer crypt.deinit();
    _ = try crypt.SetKey(&key);
    _ = try crypt.SetIv(&iv);
    _ = try crypt.TripleDes().CBC().NoPadding().Encrypt();
    try std.testing.expectEqualSlices(u8, &expected, crypt.ToBytes());

    var decrypted = try FromBytes(allocator, crypt.ToBytes());
    defer decrypted.deinit();
    _ = try decrypted.SetKey(&key);
    _ = try decrypted.SetIv(&iv);
    _ = try decrypted.TripleDes().CBC().NoPadding().Decrypt();
    try std.testing.expectEqualSlices(u8, &plain, decrypted.ToBytes());
}

test "go-cryptobin compatible TwoDES CFB PKCS7 round trip" {
    const allocator = std.testing.allocator;
    const message = "test-pass";
    const key = "dfertf12dfertf12";
    const iv = "dfertf12";
    var crypt = try FromString(allocator, message);
    defer crypt.deinit();
    _ = try crypt.SetKey(key);
    _ = try crypt.SetIv(iv);
    _ = try crypt.TwoDes().CFB().PKCS7Padding().Encrypt();

    var decrypted = try FromBytes(allocator, crypt.ToBytes());
    defer decrypted.deinit();
    _ = try decrypted.SetKey(key);
    _ = try decrypted.SetIv(iv);
    _ = try decrypted.TwoDes().CFB().PKCS7Padding().Decrypt();
    try std.testing.expectEqualSlices(u8, message, decrypted.ToBytes());
}

test "RC4-MD5 round trip" {
    const allocator = std.testing.allocator;
    var crypt = try FromString(allocator, "test-pass");
    defer crypt.deinit();
    _ = try crypt.SetKey("dfertf12dfertf12");
    _ = try crypt.SetIv("dfertf12dfertf12");
    _ = try crypt.RC4MD5().Encrypt();

    var decrypted = try FromBytes(allocator, crypt.ToBytes());
    defer decrypted.deinit();
    _ = try decrypted.SetKey("dfertf12dfertf12");
    _ = try decrypted.SetIv("dfertf12dfertf12");
    _ = try decrypted.RC4MD5().Decrypt();
    try std.testing.expectEqualSlices(u8, "test-pass", decrypted.ToBytes());
}

test "TEA and XTEA fluent round trips" {
    const allocator = std.testing.allocator;
    const key = "1234567890abcdef";
    const iv = "12345678";
    const message = "legacy data";
    var tea_value = try FromString(allocator, message);
    defer tea_value.deinit();
    _ = try tea_value.SetKey(key);
    _ = try tea_value.SetIv(iv);
    _ = try tea_value.Tea(null).CBC().PKCS7Padding().Encrypt();
    var tea_plain = try FromBytes(allocator, tea_value.ToBytes());
    defer tea_plain.deinit();
    _ = try tea_plain.SetKey(key);
    _ = try tea_plain.SetIv(iv);
    _ = try tea_plain.Tea(null).CBC().PKCS7Padding().Decrypt();
    try std.testing.expectEqualSlices(u8, message, tea_plain.ToBytes());

    var xtea_value = try FromString(allocator, message);
    defer xtea_value.deinit();
    _ = try xtea_value.SetKey(key);
    _ = try xtea_value.SetIv(iv);
    _ = try xtea_value.Xtea().CBC().PKCS7Padding().Encrypt();
    var xtea_plain = try FromBytes(allocator, xtea_value.ToBytes());
    defer xtea_plain.deinit();
    _ = try xtea_plain.SetKey(key);
    _ = try xtea_plain.SetIv(iv);
    _ = try xtea_plain.Xtea().CBC().PKCS7Padding().Decrypt();
    try std.testing.expectEqualSlices(u8, message, xtea_plain.ToBytes());
}

test "TEA rejects odd round counts" {
    const allocator = std.testing.allocator;
    var value = try FromString(allocator, "12345678");
    defer value.deinit();
    _ = try value.SetKey("1234567890abcdef");
    try std.testing.expectError(error.InvalidRounds, value.Tea(63).ECB().NoPadding().Encrypt());
}

test "SM4 fluent CBC PKCS7 round trip" {
    const allocator = std.testing.allocator;
    const key = "0123456789abcdef";
    const iv = "fedcba9876543210";
    var value = try FromString(allocator, "SM4 compatible data");
    defer value.deinit();
    _ = try value.SetKey(key);
    _ = try value.SetIv(iv);
    _ = try value.SM4().CBC().PKCS7Padding().Encrypt();
    var plain = try FromBytes(allocator, value.ToBytes());
    defer plain.deinit();
    _ = try plain.SetKey(key);
    _ = try plain.SetIv(iv);
    _ = try plain.SM4().CBC().PKCS7Padding().Decrypt();
    try std.testing.expectEqualSlices(u8, "SM4 compatible data", plain.ToBytes());
}

test "AES GCM with empty additional data" {
    const allocator = std.testing.allocator;
    var crypt = try FromString(allocator, "authenticated message");
    defer crypt.deinit();
    _ = try crypt.SetKey("1234567890abcdef");
    _ = try crypt.SetIv("123456789012");
    _ = try crypt.Aes().GCM().Encrypt();

    var decrypted = try FromBytes(allocator, crypt.ToBytes());
    defer decrypted.deinit();
    _ = try decrypted.SetKey("1234567890abcdef");
    _ = try decrypted.SetIv("123456789012");
    _ = try decrypted.Aes().GCM().Decrypt();
    try std.testing.expectEqualSlices(u8, "authenticated message", decrypted.ToBytes());
}

test "AES GCM rejects a modified ciphertext" {
    const allocator = std.testing.allocator;
    var crypt = try FromString(allocator, "authenticated message");
    defer crypt.deinit();
    _ = try crypt.SetKey("1234567890abcdef");
    _ = try crypt.SetIv("123456789012");
    _ = try crypt.Aes().GCM().Encrypt();

    var tampered = try FromBytes(allocator, crypt.ToBytes());
    defer tampered.deinit();
    tampered.data[0] ^= 1;
    _ = try tampered.SetKey("1234567890abcdef");
    _ = try tampered.SetIv("123456789012");
    try std.testing.expectError(error.AuthenticationFailed, tampered.Aes().GCM().Decrypt());
}

test "AES CCM with associated data" {
    const allocator = std.testing.allocator;
    var crypt = try FromString(allocator, "authenticated CCM message");
    defer crypt.deinit();
    _ = try crypt.SetKey("1234567890abcdef");
    _ = try crypt.SetIv("1234567890123");
    _ = try crypt.SetAdditional("header");
    _ = try crypt.Aes().CCM().Encrypt();

    var plain = try FromBytes(allocator, crypt.ToBytes());
    defer plain.deinit();
    _ = try plain.SetKey("1234567890abcdef");
    _ = try plain.SetIv("1234567890123");
    _ = try plain.SetAdditional("header");
    _ = try plain.Aes().CCM().Decrypt();
    try std.testing.expectEqualSlices(u8, "authenticated CCM message", plain.ToBytes());
}

test "AES CCM rejects modified data" {
    const allocator = std.testing.allocator;
    var crypt = try FromString(allocator, "authenticated CCM message");
    defer crypt.deinit();
    _ = try crypt.SetKey("1234567890abcdef");
    _ = try crypt.SetIv("1234567890123");
    _ = try crypt.Aes().CCM().Encrypt();
    var tampered = try FromBytes(allocator, crypt.ToBytes());
    defer tampered.deinit();
    tampered.data[0] ^= 1;
    _ = try tampered.SetKey("1234567890abcdef");
    _ = try tampered.SetIv("1234567890123");
    try std.testing.expectError(error.AuthenticationFailed, tampered.Aes().CCM().Decrypt());
}

test "AES CCM supports eight-byte tags" {
    const allocator = std.testing.allocator;
    var crypt = try FromString(allocator, "CCM short tag");
    defer crypt.deinit();
    _ = try crypt.SetKey("1234567890abcdef");
    _ = try crypt.SetIv("1234567890123");
    _ = try crypt.Aes().CCMWithTagSize(8).Encrypt();
    try std.testing.expectEqual(@as(usize, "CCM short tag".len + 8), crypt.ToBytes().len);
    var plain = try FromBytes(allocator, crypt.ToBytes());
    defer plain.deinit();
    _ = try plain.SetKey("1234567890abcdef");
    _ = try plain.SetIv("1234567890123");
    _ = try plain.Aes().CCMWithTagSize(8).Decrypt();
    try std.testing.expectEqualSlices(u8, "CCM short tag", plain.ToBytes());
}

test "AES AEAD configuration order is interchangeable" {
    const allocator = std.testing.allocator;
    var gcm = try FromString(allocator, "order independent");
    defer gcm.deinit();
    _ = try gcm.SetKey("1234567890abcdef");
    _ = try gcm.SetIv("123456789012");
    _ = try gcm.GCM().Aes().Encrypt();
    try std.testing.expectEqual(@as(usize, "order independent".len + 16), gcm.ToBytes().len);

    var ccm = try FromString(allocator, "order independent");
    defer ccm.deinit();
    _ = try ccm.SetKey("1234567890abcdef");
    _ = try ccm.SetIv("1234567890123");
    _ = try ccm.CCM().Aes().Encrypt();
    try std.testing.expectEqual(@as(usize, "order independent".len + 16), ccm.ToBytes().len);
}

test "ChaCha20-Poly1305 with additional data" {
    const allocator = std.testing.allocator;
    var crypt = try FromString(allocator, "authenticated message");
    defer crypt.deinit();
    _ = try crypt.SetKey("12345678901234567890123456789012");
    _ = try crypt.SetIv("123456789012");
    _ = try crypt.SetAdditional("header");
    _ = try crypt.Chacha20poly1305().Encrypt();

    var decrypted = try FromBytes(allocator, crypt.ToBytes());
    defer decrypted.deinit();
    _ = try decrypted.SetKey("12345678901234567890123456789012");
    _ = try decrypted.SetIv("123456789012");
    _ = try decrypted.SetAdditional("header");
    _ = try decrypted.Chacha20poly1305().Decrypt();
    try std.testing.expectEqualSlices(u8, "authenticated message", decrypted.ToBytes());
}
