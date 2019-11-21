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

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.direct_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var target: std.Target = .Native;
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
                target = try std.Target.parse(arg);
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
        .exe => return assembleExecutable(allocator, input_files.toSliceConst(), target),
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

fn assembleExecutable(allocator: *mem.Allocator, input_files: []const []const u8, target: std.Target) !void {
    const cwd = fs.Dir.cwd();

    for (input_files) |input_file| {
        const source = try cwd.readFileAlloc(allocator, input_file, math.maxInt(usize));
        var tokenizer = Tokenizer.init(source);
        while (true) {
            const token = tokenizer.next();
            if (token.id == .eof) break;
            std.debug.warn("{}\n", token.id);
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
