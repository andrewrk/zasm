const std = @import("std");
const mem = std.mem;

pub const Token = struct {
    id: Id,
    start: usize,
    end: usize,

    pub const Id = enum {
        invalid,
        identifier,
        string_literal,
        integer_literal,
        float_literal,
        char_literal,
        colon,
        comma,
        line_comment,
        period,
        slash,
        eof,
    };
};

pub const Tokenizer = struct {
    buffer: []const u8,
    index: usize,
    pending_invalid_token: ?Token,

    pub fn init(buffer: []const u8) Tokenizer {
        // Skip the UTF-8 BOM if present
        return Tokenizer{
            .buffer = buffer,
            .index = if (mem.startsWith(u8, buffer, "\xEF\xBB\xBF")) 3 else 0,
            .pending_invalid_token = null,
        };
    }

    const State = enum {
        start,
        char_literal,
        char_literal_backslash,
        char_literal_end,
        char_literal_hex_escape,
        char_literal_unicode,
        char_literal_unicode_escape,
        char_literal_unicode_escape_saw_u,
        char_literal_unicode_invalid,
        float_exponent_number,
        float_exponent_number_hex,
        float_exponent_unsigned,
        float_exponent_unsigned_hex,
        float_fraction,
        float_fraction_hex,
        identifier,
        integer_literal,
        integer_literal_with_radix,
        integer_literal_with_radix_hex,
        line_comment,
        number_dot,
        number_dot_hex,
        slash,
        string_literal,
        string_literal_backslash,
        zero,
    };

    pub fn next(self: *Tokenizer) Token {
        if (self.pending_invalid_token) |token| {
            self.pending_invalid_token = null;
            return token;
        }
        const start_index = self.index;
        var state: State = .start;
        var result = Token{
            .id = .eof,
            .start = self.index,
            .end = undefined,
        };
        var seen_escape_digits: usize = undefined;
        var remaining_code_units: usize = undefined;
        while (self.index < self.buffer.len) : (self.index += 1) {
            const c = self.buffer[self.index];
            switch (state) {
                .start => switch (c) {
                    ' ', '\n', '\t', '\r' => {
                        result.start = self.index + 1;
                    },
                    '"' => {
                        state = .string_literal;
                        result.id = .string_literal;
                    },
                    '\'' => {
                        state = .char_literal;
                    },
                    'a'...'z', 'A'...'Z', '_' => {
                        state = .identifier;
                        result.id = .identifier;
                    },
                    ',' => {
                        result.id = .comma;
                        self.index += 1;
                        break;
                    },
                    ':' => {
                        result.id = .colon;
                        self.index += 1;
                        break;
                    },
                    '.' => {
                        result.id = .period;
                        self.index += 1;
                        break;
                    },
                    '/' => {
                        state = .slash;
                    },
                    '0' => {
                        state = .zero;
                        result.id = .integer_literal;
                    },
                    '1'...'9' => {
                        state = .integer_literal;
                        result.id = .integer_literal;
                    },
                    else => {
                        result.id = .invalid;
                        self.index += 1;
                        break;
                    },
                },

                .identifier => switch (c) {
                    'a'...'z', 'A'...'Z', '_', '0'...'9' => {},
                    else => break,
                },
                .string_literal => switch (c) {
                    '\\' => {
                        state = .string_literal_backslash;
                    },
                    '"' => {
                        self.index += 1;
                        break;
                    },
                    '\n', '\r' => break, // Look for this error later.
                    else => self.checkLiteralCharacter(),
                },

                .string_literal_backslash => switch (c) {
                    '\n', '\r' => break, // Look for this error later.
                    else => {
                        state = .string_literal;
                    },
                },

                .char_literal => switch (c) {
                    '\\' => {
                        state = .char_literal_backslash;
                    },
                    '\'', 0x80...0xbf, 0xf8...0xff => {
                        result.id = .invalid;
                        break;
                    },
                    0xc0...0xdf => { // 110xxxxx
                        remaining_code_units = 1;
                        state = .char_literal_unicode;
                    },
                    0xe0...0xef => { // 1110xxxx
                        remaining_code_units = 2;
                        state = .char_literal_unicode;
                    },
                    0xf0...0xf7 => { // 11110xxx
                        remaining_code_units = 3;
                        state = .char_literal_unicode;
                    },
                    else => {
                        state = .char_literal_end;
                    },
                },

                .char_literal_backslash => switch (c) {
                    '\n' => {
                        result.id = .invalid;
                        break;
                    },
                    'x' => {
                        state = .char_literal_hex_escape;
                        seen_escape_digits = 0;
                    },
                    'u' => {
                        state = .char_literal_unicode_escape_saw_u;
                    },
                    else => {
                        state = .char_literal_end;
                    },
                },

                .char_literal_hex_escape => switch (c) {
                    '0'...'9', 'a'...'f', 'A'...'F' => {
                        seen_escape_digits += 1;
                        if (seen_escape_digits == 2) {
                            state = .char_literal_end;
                        }
                    },
                    else => {
                        result.id = .invalid;
                        break;
                    },
                },

                .char_literal_unicode_escape_saw_u => switch (c) {
                    '{' => {
                        state = .char_literal_unicode_escape;
                        seen_escape_digits = 0;
                    },
                    else => {
                        result.id = .invalid;
                        state = .char_literal_unicode_invalid;
                    },
                },

                .char_literal_unicode_escape => switch (c) {
                    '0'...'9', 'a'...'f', 'A'...'F' => {
                        seen_escape_digits += 1;
                    },
                    '}' => {
                        if (seen_escape_digits == 0) {
                            result.id = .invalid;
                            state = .char_literal_unicode_invalid;
                        } else {
                            state = .char_literal_end;
                        }
                    },
                    else => {
                        result.id = .invalid;
                        state = .char_literal_unicode_invalid;
                    },
                },

                .char_literal_unicode_invalid => switch (c) {
                    // Keep consuming characters until an obvious stopping point.
                    // This consolidates e.g. `u{0ab1Q}` into a single invalid token
                    // instead of creating the tokens `u{0ab1`, `Q`, `}`
                    '0'...'9', 'a'...'z', 'A'...'Z', '}' => {},
                    else => break,
                },

                .char_literal_end => switch (c) {
                    '\'' => {
                        result.id = .char_literal;
                        self.index += 1;
                        break;
                    },
                    else => {
                        result.id = .invalid;
                        break;
                    },
                },

                .char_literal_unicode => switch (c) {
                    0x80...0xbf => {
                        remaining_code_units -= 1;
                        if (remaining_code_units == 0) {
                            state = .char_literal_end;
                        }
                    },
                    else => {
                        result.id = .invalid;
                        break;
                    },
                },

                .slash => switch (c) {
                    '/' => {
                        state = .line_comment;
                        result.id = .line_comment;
                    },
                    else => {
                        result.id = .slash;
                        break;
                    },
                },
                .line_comment => switch (c) {
                    '\n' => break,
                    else => self.checkLiteralCharacter(),
                },
                .zero => switch (c) {
                    'b', 'o' => {
                        state = .integer_literal_with_radix;
                    },
                    'x' => {
                        state = .integer_literal_with_radix_hex;
                    },
                    else => {
                        // reinterpret as a normal number
                        self.index -= 1;
                        state = .integer_literal;
                    },
                },
                .integer_literal => switch (c) {
                    '.' => {
                        state = .number_dot;
                    },
                    'p', 'P', 'e', 'E' => {
                        state = .float_exponent_unsigned;
                    },
                    '0'...'9' => {},
                    else => break,
                },
                .integer_literal_with_radix => switch (c) {
                    '.' => {
                        state = .number_dot;
                    },
                    '0'...'9' => {},
                    else => break,
                },
                .integer_literal_with_radix_hex => switch (c) {
                    '.' => {
                        state = .number_dot_hex;
                    },
                    'p', 'P' => {
                        state = .float_exponent_unsigned_hex;
                    },
                    '0'...'9', 'a'...'f', 'A'...'F' => {},
                    else => break,
                },
                .number_dot => switch (c) {
                    '.' => {
                        self.index -= 1;
                        state = .start;
                        break;
                    },
                    else => {
                        self.index -= 1;
                        result.id = .float_literal;
                        state = .float_fraction;
                    },
                },
                .number_dot_hex => switch (c) {
                    '.' => {
                        self.index -= 1;
                        state = .start;
                        break;
                    },
                    else => {
                        self.index -= 1;
                        result.id = .float_literal;
                        state = .float_fraction_hex;
                    },
                },
                .float_fraction => switch (c) {
                    'e', 'E' => {
                        state = .float_exponent_unsigned;
                    },
                    '0'...'9' => {},
                    else => break,
                },
                .float_fraction_hex => switch (c) {
                    'p', 'P' => {
                        state = .float_exponent_unsigned_hex;
                    },
                    '0'...'9', 'a'...'f', 'A'...'F' => {},
                    else => break,
                },
                .float_exponent_unsigned => switch (c) {
                    '+', '-' => {
                        state = .float_exponent_number;
                    },
                    else => {
                        // reinterpret as a normal exponent number
                        self.index -= 1;
                        state = .float_exponent_number;
                    },
                },
                .float_exponent_unsigned_hex => switch (c) {
                    '+', '-' => {
                        state = .float_exponent_number_hex;
                    },
                    else => {
                        // reinterpret as a normal exponent number
                        self.index -= 1;
                        state = .float_exponent_number_hex;
                    },
                },
                .float_exponent_number => switch (c) {
                    '0'...'9' => {},
                    else => break,
                },
                .float_exponent_number_hex => switch (c) {
                    '0'...'9', 'a'...'f', 'A'...'F' => {},
                    else => break,
                },
            }
        } else if (self.index == self.buffer.len) {
            switch (state) {
                .start,
                .integer_literal,
                .integer_literal_with_radix,
                .integer_literal_with_radix_hex,
                .float_fraction,
                .float_fraction_hex,
                .float_exponent_number,
                .float_exponent_number_hex,
                .string_literal, // find this error later
                => {},

                .identifier => {},

                .line_comment => {
                    result.id = Token.Id.line_comment;
                },

                .number_dot,
                .number_dot_hex,
                .float_exponent_unsigned,
                .float_exponent_unsigned_hex,
                .char_literal,
                .char_literal_backslash,
                .char_literal_hex_escape,
                .char_literal_unicode_escape_saw_u,
                .char_literal_unicode_escape,
                .char_literal_unicode_invalid,
                .char_literal_end,
                .char_literal_unicode,
                .string_literal_backslash,
                => {
                    result.id = .invalid;
                },

                .slash => {
                    result.id = .slash;
                },
                .zero => {
                    result.id = .integer_literal;
                },
            }
        }

        if (result.id == .eof) {
            if (self.pending_invalid_token) |token| {
                self.pending_invalid_token = null;
                return token;
            }
        }

        result.end = self.index;
        return result;
    }

    fn checkLiteralCharacter(self: *Tokenizer) void {
        if (self.pending_invalid_token != null) return;
        const invalid_length = self.getInvalidCharacterLength();
        if (invalid_length == 0) return;
        self.pending_invalid_token = Token{
            .id = .invalid,
            .start = self.index,
            .end = self.index + invalid_length,
        };
    }

    fn getInvalidCharacterLength(self: *Tokenizer) u3 {
        const c0 = self.buffer[self.index];
        if (c0 < 0x80) {
            if (c0 < 0x20 or c0 == 0x7f) {
                // ascii control codes are never allowed
                // (note that \n was checked before we got here)
                return 1;
            }
            // looks fine to me.
            return 0;
        } else {
            // check utf8-encoded character.
            const length = std.unicode.utf8ByteSequenceLength(c0) catch return 1;
            if (self.index + length > self.buffer.len) {
                return @intCast(u3, self.buffer.len - self.index);
            }
            const bytes = self.buffer[self.index .. self.index + length];
            switch (length) {
                2 => {
                    const value = std.unicode.utf8Decode2(bytes) catch return length;
                    if (value == 0x85) return length; // U+0085 (NEL)
                },
                3 => {
                    const value = std.unicode.utf8Decode3(bytes) catch return length;
                    if (value == 0x2028) return length; // U+2028 (LS)
                    if (value == 0x2029) return length; // U+2029 (PS)
                },
                4 => {
                    _ = std.unicode.utf8Decode4(bytes) catch return length;
                },
                else => unreachable,
            }
            self.index += length - 1;
            return 0;
        }
    }
};

test "tokenizer - char literal with hex escape" {
    testTokenize(
        \\'\x1b'
    , [_]Token.Id{.char_literal});
    testTokenize(
        \\'\x1'
    , [_]Token.Id{ .invalid, .invalid });
}

test "tokenizer - char literal with unicode escapes" {
    // Valid unicode escapes
    testTokenize(
        \\'\u{3}'
    , [_]Token.Id{.char_literal});
    testTokenize(
        \\'\u{01}'
    , [_]Token.Id{.char_literal});
    testTokenize(
        \\'\u{2a}'
    , [_]Token.Id{.char_literal});
    testTokenize(
        \\'\u{3f9}'
    , [_]Token.Id{.char_literal});
    testTokenize(
        \\'\u{6E09aBc1523}'
    , [_]Token.Id{.char_literal});
    testTokenize(
        \\"\u{440}"
    , [_]Token.Id{.string_literal});

    // Invalid unicode escapes
    testTokenize(
        \\'\u'
    , [_]Token.Id{.invalid});
    testTokenize(
        \\'\u{{'
    , [_]Token.Id{ .invalid, .invalid });
    testTokenize(
        \\'\u{}'
    , [_]Token.Id{ .invalid, .invalid });
    testTokenize(
        \\'\u{s}'
    , [_]Token.Id{ .invalid, .invalid });
    testTokenize(
        \\'\u{2z}'
    , [_]Token.Id{ .invalid, .invalid });
    testTokenize(
        \\'\u{4a'
    , [_]Token.Id{.invalid});

    // Test old-style unicode literals
    testTokenize(
        \\'\u0333'
    , [_]Token.Id{ .invalid, .invalid });
    testTokenize(
        \\'\U0333'
    , [_]Token.Id{ .invalid, .integer_literal, .invalid });
}

test "tokenizer - char literal with unicode code point" {
    testTokenize(
        \\'💩'
    , [_]Token.Id{.char_literal});
}

test "tokenizer - line comment followed by identifier" {
    testTokenize(
        \\    Unexpected,
        \\    // another
        \\    Another,
    , [_]Token.Id{
        .identifier,
        .comma,
        .line_comment,
        .identifier,
        .comma,
    });
}

test "tokenizer - UTF-8 BOM is recognized and skipped" {
    testTokenize("\xEF\xBB\xBFa.\n", [_]Token.Id{
        .identifier,
        .period,
    });
}

fn testTokenize(source: []const u8, expected_tokens: []const Token.Id) void {
    var tokenizer = Tokenizer.init(source);
    for (expected_tokens) |expected_token_id| {
        const token = tokenizer.next();
        if (token.id != expected_token_id) {
            std.debug.panic("expected {}, found {}\n", @tagName(expected_token_id), @tagName(token.id));
        }
    }
    const last_token = tokenizer.next();
    std.testing.expect(last_token.id == .eof);
}
