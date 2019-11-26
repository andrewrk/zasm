const std = @import("std");
const Tokenizer = @import("tokenize.zig").Tokenizer;
const Token = @import("tokenize.zig").Token;
const mem = std.mem;
const fs = std.fs;
const process = std.process;
const math = std.math;
const data = @import("data.zig");
const parseStringLiteral = std.zig.parseStringLiteral;
const elf = std.elf;
const assert = std.debug.assert;

const Cmd = enum {
    exe,
    obj,
    dis,
    targets,
    tokenize,
};

const Assembly = struct {
    allocator: *mem.Allocator,
    input_files: []const []const u8,
    target: std.Target,
    errors: std.ArrayList(Error),
    entry_addr: u64,

    pub const SourceInfo = struct {
        token: Token,
        source: []const u8,
        file_name: []const u8,
    };

    const Error = union(enum) {
        unexpected_token: struct {
            source_info: SourceInfo,
        },
        unrecognized_directive: struct {
            source_info: SourceInfo,
        },
        unrecognized_instruction: struct {
            source_info: SourceInfo,
        },
        symbol_outside_section: struct {
            source_info: SourceInfo,
        },
        duplicate_symbol: struct {
            source_info: SourceInfo,
            other_symbol: Token,
        },
        bad_integer_literal: struct {
            source_info: SourceInfo,
        },
        instr_outside_symbol: struct {
            source_info: SourceInfo,
        },
        bad_string_literal: struct {
            source_info: SourceInfo,
            bad_index: usize,
        },

        fn printToStream(stream: var, comptime message: []const u8, source_info: SourceInfo, args: ...) !void {
            const loc = tokenLocation(source_info.source, source_info.token);
            try stream.print(
                "{}:{}:{}: " ++ message,
                source_info.file_name,
                loc.line + 1,
                loc.column + 1,
                args,
            );
        }

        fn render(self: Error, stream: var) !void {
            switch (self) {
                .unexpected_token => |info| {
                    try printToStream(
                        stream,
                        "error: unexpected token: {}\n",
                        info.source_info,
                        @tagName(info.source_info.token.id),
                    );
                },
                .unrecognized_directive => |info| {
                    const si = info.source_info;
                    try printToStream(
                        stream,
                        "error: unrecognized directive: {}\n",
                        si,
                        si.source[si.token.start..si.token.end],
                    );
                },
                .unrecognized_instruction => |info| {
                    const si = info.source_info;
                    try printToStream(
                        stream,
                        "error: unrecognized instruction: {}\n",
                        si,
                        si.source[si.token.start..si.token.end],
                    );
                },
                .symbol_outside_section => |info| {
                    const si = info.source_info;
                    try printToStream(
                        stream,
                        "error: symbol outside section: {}\n",
                        si,
                        si.source[si.token.start..si.token.end],
                    );
                },
                .bad_integer_literal => |info| {
                    const si = info.source_info;
                    try printToStream(
                        stream,
                        "error: invalid integer literal: {}\n",
                        si,
                        si.source[si.token.start..si.token.end],
                    );
                },
                .bad_string_literal => |info| {
                    const si = info.source_info;
                    try printToStream(
                        stream,
                        "error: invalid string literal at index {}: {}\n",
                        si,
                        info.bad_index,
                        si.source[si.token.start..si.token.end],
                    );
                },
                .instr_outside_symbol => |info| {
                    const si = info.source_info;
                    try printToStream(
                        stream,
                        "error: instruction outside symbol\n",
                        si,
                    );
                },
                .duplicate_symbol => |info| {
                    const si = info.source_info;
                    const other_loc = tokenLocation(si.source, info.other_symbol);
                    try printToStream(
                        stream,
                        "error: duplicate symbol: {}\n" ++
                            "{}:{}:{}: note: original definition. \n",
                        si,
                        si.source[si.token.start..si.token.end],

                        si.file_name,
                        other_loc.line + 1,
                        other_loc.column + 1,
                    );
                },
            }
        }
    };
};

const Location = struct {
    line: usize,
    column: usize,
    line_start: usize,
    line_end: usize,
};

fn tokenLocation(source: []const u8, token: Token) Location {
    const start_index = 0;
    var loc = Location{
        .line = 0,
        .column = 0,
        .line_start = start_index,
        .line_end = source.len,
    };
    const token_start = token.start;
    for (source[start_index..]) |c, i| {
        if (i + start_index == token_start) {
            loc.line_end = i + start_index;
            while (loc.line_end < source.len and source[loc.line_end] != '\n') : (loc.line_end += 1) {}
            return loc;
        }
        if (c == '\n') {
            loc.line += 1;
            loc.column = 0;
            loc.line_start = i + 1;
        } else {
            loc.column += 1;
        }
    }
    return loc;
}

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.direct_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var assembly = Assembly{
        .allocator = allocator,
        .target = .Native,
        .input_files = undefined,
        .errors = std.ArrayList(Assembly.Error).init(allocator),
        .entry_addr = 0x80000000,
    };
    var input_files = std.ArrayList([]const u8).init(allocator);
    var maybe_cmd: ?Cmd = null;
    var debug_errors = false;

    const args = try process.argsAlloc(allocator);
    var arg_i: usize = 1;
    while (arg_i < args.len) : (arg_i += 1) {
        const full_arg = args[arg_i];
        if (mem.startsWith(u8, full_arg, "-")) {
            const arg = full_arg[1..];
            if (mem.eql(u8, arg, "help")) {
                try dumpUsage(std.io.getStdOut());
                return;
            } else if (mem.eql(u8, arg, "target")) {
                assembly.target = try std.Target.parse(arg);
            } else if (mem.eql(u8, arg, "debug-errors")) {
                debug_errors = true;
            } else {
                std.debug.warn("Invalid parameter: {}\n", full_arg);
                dumpStdErrUsageAndExit();
            }
        } else if (maybe_cmd == null) {
            inline for (std.meta.fields(Cmd)) |field| {
                if (mem.eql(u8, full_arg, field.name)) {
                    maybe_cmd = @field(Cmd, field.name);
                    break;
                }
            } else {
                std.debug.warn("Invalid command: {}\n", full_arg);
                dumpStdErrUsageAndExit();
            }
        } else {
            try input_files.append(full_arg);
        }
    }

    const cmd = maybe_cmd orelse {
        std.debug.warn("Expected a command parameter\n");
        dumpStdErrUsageAndExit();
    };

    switch (cmd) {
        .targets => {
            try std.io.getStdOut().write(
                \\x86_64-linux
                \\
            );
            return;
        },
        .exe => {
            assembly.input_files = input_files.toSliceConst();
            assembleExecutable(&assembly) catch |err| switch (err) {
                error.ParseFailure => {
                    const stream = &std.io.getStdErr().outStream().stream;
                    for (assembly.errors.toSliceConst()) |asm_err| {
                        try asm_err.render(stream);
                    }
                    if (debug_errors) {
                        return err;
                    } else {
                        process.exit(1);
                    }
                },
                else => |e| return e,
            };
        },
        .obj => {
            std.debug.warn("object files not yet implemented\n");
            process.exit(1);
        },
        .dis => {
            std.debug.warn("disassembly not yet implemented\n");
            process.exit(1);
        },
        .tokenize => {
            const stdout = &std.io.getStdOut().outStream().stream;
            const cwd = fs.Dir.cwd();
            for (input_files.toSliceConst()) |input_file| {
                const source = try cwd.readFileAlloc(allocator, input_file, math.maxInt(usize));
                var tokenizer = Tokenizer.init(source);
                while (true) {
                    const token = tokenizer.next();
                    if (token.id == .eof) break;
                    try stdout.print("{}: {}\n", @tagName(token.id), source[token.start..token.end]);
                }
            }
        },
    }
}

const Arg = union(enum) {
    register: data.Register,
    immediate: u64,
    symbol_ref: []const u8,
};

const AsmFile = struct {
    source: []const u8,
    file_name: []const u8,
    tokenizer: Tokenizer,
    assembly: *Assembly,
    current_section: ?*Section = null,
    current_symbol: ?*Symbol = null,
    sections: SectionTable,
    globals: GlobalSet,
    put_back_buffer: [1]Token,
    put_back_count: u1,
    symbols: SymbolTable,

    const SectionTable = std.StringHashMap(*Section);
    const SymbolTable = std.StringHashMap(*Symbol);
    const GlobalSet = std.StringHashMap(void);

    const Section = struct {
        name: []const u8,
        layout: std.ArrayList(*Symbol),
    };

    const Instruction = struct {
        props: *const data.Instruction,

        /// Relative to the containing Symbol
        addr_offset: u64,

        args: []Arg,
    };

    const Symbol = struct {
        /// Relative to the containing Section
        /// `undefined` until a second pass when addresses are calculated.
        addr_offset: u64,

        /// Starts at 0. Increments with instructions being added.
        size: u64,

        source_token: Token,
        name: []const u8,
        section: *Section,

        ops: std.ArrayList(PseudoOp),
    };

    const PseudoOp = union(enum) {
        instruction: Instruction,
        data: []const u8,
    };

    fn tokenSlice(asm_file: AsmFile, token: Token) []const u8 {
        return asm_file.source[token.start..token.end];
    }

    fn findOrCreateSection(self: *AsmFile, name: []const u8) !*Section {
        const gop = try self.sections.getOrPut(name);
        if (gop.found_existing) {
            return gop.kv.value;
        }
        const section = try self.sections.allocator.create(Section);
        section.* = Section{
            .name = name,
            .layout = std.ArrayList(*Symbol).init(self.sections.allocator),
        };
        gop.kv.value = section;
        return section;
    }

    fn setCurrentSection(self: *AsmFile, name: []const u8) !void {
        self.current_section = try self.findOrCreateSection("text");
    }

    fn beginSymbol(self: *AsmFile, source_token: Token, name: []const u8) !void {
        const current_section = self.current_section orelse {
            try self.assembly.errors.append(.{
                .symbol_outside_section = .{ .source_info = newSourceInfo(self, source_token) },
            });
            return error.ParseFailure;
        };
        const symbol = try self.symbols.allocator.create(Symbol);
        symbol.* = Symbol{
            .addr_offset = undefined,
            .size = 0,
            .source_token = source_token,
            .name = name,
            .section = current_section,
            .ops = std.ArrayList(PseudoOp).init(self.assembly.allocator),
        };
        if (try self.symbols.put(name, symbol)) |existing_entry| {
            try self.assembly.errors.append(.{
                .duplicate_symbol = .{
                    .source_info = newSourceInfo(self, source_token),
                    .other_symbol = existing_entry.value.source_token,
                },
            });
            return error.ParseFailure;
        }
        try current_section.layout.append(symbol);
        self.current_symbol = symbol;
    }

    fn addGlobal(self: *AsmFile, name: []const u8) !void {
        _ = try self.globals.put(name, {});
    }

    fn nextToken(self: *AsmFile) Token {
        if (self.put_back_count == 0) {
            return self.tokenizer.next();
        } else {
            self.put_back_count -= 1;
            return self.put_back_buffer[self.put_back_count];
        }
    }

    fn eatToken(self: *AsmFile, id: Token.Id) ?Token {
        const token = self.nextToken();
        if (token.id == id) return token;
        self.putBackToken(token);
        return null;
    }

    fn putBackToken(self: *AsmFile, token: Token) void {
        self.put_back_buffer[self.put_back_count] = token;
        self.put_back_count += 1;
    }

    fn expectToken(asm_file: *AsmFile, id: Token.Id) !Token {
        const token = asm_file.nextToken();
        if (token.id != id) {
            try asm_file.assembly.errors.append(.{
                .unexpected_token = .{ .source_info = newSourceInfo(asm_file, token) },
            });
            return error.ParseFailure;
        }
        return token;
    }

    fn getCurrentSymbol(asm_file: *AsmFile, source_token: Token) !*Symbol {
        return asm_file.current_symbol orelse {
            try asm_file.assembly.errors.append(.{
                .instr_outside_symbol = .{ .source_info = newSourceInfo(asm_file, source_token) },
            });
            return error.ParseFailure;
        };
    }
};

fn newSourceInfo(asm_file: *AsmFile, tok: Token) Assembly.SourceInfo {
    return .{
        .token = tok,
        .source = asm_file.source,
        .file_name = asm_file.file_name,
    };
}

fn assembleExecutable(assembly: *Assembly) !void {
    const cwd = fs.Dir.cwd();

    for (assembly.input_files) |input_file| {
        var asm_file = AsmFile{
            .assembly = assembly,
            .file_name = input_file,
            .sections = AsmFile.SectionTable.init(assembly.allocator),
            .globals = AsmFile.GlobalSet.init(assembly.allocator),
            .symbols = AsmFile.SymbolTable.init(assembly.allocator),
            .source = try cwd.readFileAlloc(assembly.allocator, input_file, math.maxInt(usize)),
            .tokenizer = undefined,
            .put_back_buffer = undefined,
            .put_back_count = 0,
        };
        asm_file.tokenizer = Tokenizer.init(asm_file.source);
        while (true) {
            const token = asm_file.nextToken();
            switch (token.id) {
                .eof => break,
                .period => {
                    const dir_ident = try asm_file.expectToken(.identifier);
                    const dir_name = asm_file.tokenSlice(dir_ident);
                    if (mem.eql(u8, dir_name, "text")) {
                        try asm_file.setCurrentSection("text");
                    } else if (mem.eql(u8, dir_name, "globl")) {
                        while (true) {
                            const ident = try asm_file.expectToken(.identifier);
                            try asm_file.addGlobal(asm_file.tokenSlice(ident));
                            if (asm_file.eatToken(.comma)) |_| continue else break;
                        }
                    } else if (mem.eql(u8, dir_name, "section")) {
                        _ = try asm_file.expectToken(.period);
                        const sect_name_token = try asm_file.expectToken(.identifier);
                        const sect_name = asm_file.tokenSlice(sect_name_token);
                        try asm_file.setCurrentSection(sect_name);
                        _ = try asm_file.expectToken(.comma);
                        // TODO support this string literal doing anything
                        _ = try asm_file.expectToken(.string_literal);
                    } else if (mem.eql(u8, dir_name, "ascii")) {
                        const current_symbol = try asm_file.getCurrentSymbol(dir_ident);

                        const str_lit_tok = try asm_file.expectToken(.string_literal);
                        const str_lit = asm_file.tokenSlice(str_lit_tok);
                        var bad_index: usize = undefined;
                        const bytes = parseStringLiteral(
                            assembly.allocator,
                            str_lit,
                            &bad_index,
                        ) catch |err| switch (err) {
                            error.InvalidCharacter => {
                                try assembly.errors.append(.{
                                    .bad_string_literal = .{
                                        .source_info = newSourceInfo(&asm_file, str_lit_tok),
                                        .bad_index = bad_index,
                                    },
                                });
                                return error.ParseFailure;
                            },
                            error.OutOfMemory => |e| return e,
                        };

                        try current_symbol.ops.append(.{ .data = bytes });
                        current_symbol.size += bytes.len;
                    } else {
                        try assembly.errors.append(.{
                            .unrecognized_directive = .{ .source_info = newSourceInfo(&asm_file, dir_ident) },
                        });
                        return error.ParseFailure;
                    }
                },
                .identifier => {
                    if (asm_file.eatToken(.colon)) |_| {
                        const symbol_name = asm_file.tokenSlice(token);
                        try asm_file.beginSymbol(token, symbol_name);
                    } else {
                        const wanted_instr_name = asm_file.tokenSlice(token);
                        const inst = for (data.instructions) |*inst| {
                            if (mem.eql(u8, inst.name, wanted_instr_name)) {
                                break inst;
                            }
                        } else {
                            try assembly.errors.append(.{
                                .unrecognized_instruction = .{ .source_info = newSourceInfo(&asm_file, token) },
                            });
                            return error.ParseFailure;
                        };
                        const current_symbol = try asm_file.getCurrentSymbol(token);
                        var args_left: usize = inst.args.len;
                        var first = true;
                        var args = std.ArrayList(Arg).init(assembly.allocator);
                        while (args_left != 0) : (args_left -= 1) {
                            if (first) {
                                first = false;
                            } else {
                                _ = try asm_file.expectToken(.comma);
                            }
                            const arg_token = asm_file.nextToken();
                            const arg_text = asm_file.tokenSlice(arg_token);
                            var arg: Arg = undefined;
                            switch (arg_token.id) {
                                .integer_literal => {
                                    var text: []const u8 = undefined;
                                    var base: u8 = undefined;
                                    if (mem.startsWith(u8, arg_text, "0x")) {
                                        base = 16;
                                        text = arg_text[2..];
                                    } else if (mem.startsWith(u8, arg_text, "0b")) {
                                        base = 2;
                                        text = arg_text[2..];
                                    } else if (mem.startsWith(u8, arg_text, "0o")) {
                                        base = 8;
                                        text = arg_text[2..];
                                    } else {
                                        base = 10;
                                        text = arg_text;
                                    }
                                    const imm = std.fmt.parseUnsigned(u64, text, base) catch |err| {
                                        try asm_file.assembly.errors.append(.{
                                            .bad_integer_literal = .{ .source_info = newSourceInfo(&asm_file, arg_token) },
                                        });
                                        return error.ParseFailure;
                                    };
                                    arg = Arg{ .immediate = imm };
                                },
                                .identifier => {
                                    inline for (std.meta.fields(data.Register)) |field| {
                                        if (mem.eql(u8, arg_text, field.name)) {
                                            const reg = @field(data.Register, field.name);
                                            arg = Arg{ .register = reg };
                                            break;
                                        }
                                    } else {
                                        arg = Arg{ .symbol_ref = arg_text };
                                    }
                                },
                                else => {
                                    try asm_file.assembly.errors.append(.{
                                        .unexpected_token = .{ .source_info = newSourceInfo(&asm_file, arg_token) },
                                    });
                                    return error.ParseFailure;
                                },
                            }
                            try args.append(arg);
                        }

                        try current_symbol.ops.append(.{
                            .instruction = .{
                                .props = inst,
                                .addr_offset = current_symbol.size,
                                .args = args.toSliceConst(),
                            },
                        });
                        current_symbol.size += inst.size;
                    }
                },
                else => {
                    try assembly.errors.append(.{
                        .unexpected_token = .{ .source_info = newSourceInfo(&asm_file, token) },
                    });
                    return error.ParseFailure;
                },
            }
        }

        try assembleExePass2(assembly, &asm_file);
    }
}

fn assembleExePass2(assembly: *Assembly, asm_file: *AsmFile) !void {
    const ptr_bit_width = assembly.target.getArchPtrBitWidth();
    const endian = assembly.target.getArch().endian();
    var hdr_buf: [@sizeOf(elf.Elf64_Ehdr) + @sizeOf(elf.Elf64_Phdr)]u8 = undefined;
    var index: usize = 0;

    mem.copy(u8, hdr_buf[index..], "\x7fELF");
    index += 4;

    hdr_buf[index] = switch (ptr_bit_width) {
        32 => 1,
        64 => 2,
        else => return error.UnsupportedArchitecture,
    };
    index += 1;

    hdr_buf[index] = switch (endian) {
        .Little => 1,
        .Big => 2,
    };
    index += 1;

    hdr_buf[index] = 1; // ELF version
    index += 1;

    // OS ABI, often set to 0 regardless of target platform
    // ABI Version, possibly used by glibc but not by static executables
    // padding
    mem.set(u8, hdr_buf[index..][0..9], 0);
    index += 9;

    assert(index == 16);

    // TODO: https://github.com/ziglang/zig/issues/863 makes this (and all following) @ptrCast unnecessary
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), @enumToInt(elf.ET.EXEC), endian);
    index += 2;

    const machine = assembly.target.getArch().toElfMachine();
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), @enumToInt(machine), endian);
    index += 2;

    // ELF Version, again
    mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), 1, endian);
    index += 4;

    switch (ptr_bit_width) {
        32 => {
            // e_entry
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), @intCast(u32, assembly.entry_addr), endian);
            index += 4;

            // e_phoff
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), @sizeOf(elf.Elf32_Ehdr), endian);
            index += 4;

            // e_shoff
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), 0, endian);
            index += 4;
        },
        64 => {
            // e_entry
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), assembly.entry_addr, endian);
            index += 8;

            // e_phoff
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), @sizeOf(elf.Elf64_Ehdr), endian);
            index += 8;

            // e_shoff
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), 0, endian);
            index += 8;
        },
        else => unreachable,
    }

    // e_flags
    mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), 0, endian);
    index += 4;

    const e_ehsize: u16 = switch (ptr_bit_width) {
        32 => @sizeOf(elf.Elf32_Ehdr),
        64 => @sizeOf(elf.Elf64_Ehdr),
        else => unreachable,
    };
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_ehsize, endian);
    index += 2;

    const e_phentsize: u16 = switch (ptr_bit_width) {
        32 => @sizeOf(elf.Elf32_Phdr),
        64 => @sizeOf(elf.Elf64_Phdr),
        else => unreachable,
    };
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_phentsize, endian);
    index += 2;

    const e_phnum = 1;
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_phnum, endian);
    index += 2;

    const e_shentsize: u16 = switch (ptr_bit_width) {
        32 => @sizeOf(elf.Elf32_Shdr),
        64 => @sizeOf(elf.Elf64_Shdr),
        else => unreachable,
    };
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_shentsize, endian);
    index += 2;

    const e_shnum = 0;
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_shnum, endian);
    index += 2;

    const e_shstrndx = 0;
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_shstrndx, endian);
    index += 2;

    assert(index == e_ehsize);
}

fn dumpStdErrUsageAndExit() noreturn {
    dumpUsage(std.io.getStdErr()) catch {};
    process.exit(1);
}

fn dumpUsage(file: fs.File) !void {
    try file.write(
        \\Usage: zasm [command] [options]
        \\
        \\Commands:
        \\  exe                  create an executable file
        \\  obj                  create an object file
        \\  dis                  disassemble a binary into source
        \\  targets              list the supported targets to stdout
        \\  tokenize             (debug) tokenize the input files
        \\
        \\Options:
        \\  -help                dump this help text to stdout
        \\  -target [arch]-[os]  specify the target for positional arguments
        \\  -debug-errors        show stack trace on error
        \\
    );
}

test "" {
    _ = Token;
    _ = Tokenizer;
}
