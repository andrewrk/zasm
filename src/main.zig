const std = @import("std");
const Tokenizer = @import("tokenize.zig").Tokenizer;
const Token = @import("tokenize.zig").Token;
const mem = std.mem;
const fs = std.fs;
const process = std.process;
const math = std.math;

const Cmd = enum {
    exe,
    obj,
    dis,
    targets,
};

const Assembly = struct {
    allocator: *mem.Allocator,
    input_files: []const []const u8,
    target: std.Target,
    current_section: ?*Section,
    errors: std.ArrayList(Error),

    const Error = union(enum) {
        unexpected_token: struct {
            token: Token,
            source: []const u8,
            file_name: []const u8,
        },

        fn render(self: Error, stream: var) !void {
            switch (self) {
                .unexpected_token => |unexpected_token| {
                    const loc = tokenLocation(unexpected_token.source, unexpected_token.token);
                    try stream.print(
                        "{}:{}:{}: error: unexpected token: {}\n",
                        unexpected_token.file_name,
                        loc.line + 1,
                        loc.column + 1,
                        @tagName(unexpected_token.token.id),
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

const Section = struct {
    name: []const u8,
};

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.direct_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var assembly = Assembly{
        .allocator = allocator,
        .target = .Native,
        .input_files = undefined,
        .current_section = null,
        .errors = std.ArrayList(Assembly.Error).init(allocator),
    };
    var input_files = std.ArrayList([]const u8).init(allocator);
    var maybe_cmd: ?Cmd = null;

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
    }
}

fn assembleExecutable(assembly: *Assembly) !void {
    const cwd = fs.Dir.cwd();

    for (assembly.input_files) |input_file| {
        const source = try cwd.readFileAlloc(assembly.allocator, input_file, math.maxInt(usize));
        var tokenizer = Tokenizer.init(source);
        while (true) {
            const token = tokenizer.next();
            switch (token.id) {
                .eof => break,
                else => {
                    try assembly.errors.append(.{
                        .unexpected_token = .{
                            .token = token,
                            .source = source,
                            .file_name = input_file,
                        },
                    });
                    return error.ParseFailure;
                },
            }
        }
    }
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
        \\
        \\Options:
        \\  -help                dump this help text to stdout
        \\  -target [arch]-[os]  specify the target for positional arguments
        \\
    );
}

test "" {
    _ = Token;
    _ = Tokenizer;
}
