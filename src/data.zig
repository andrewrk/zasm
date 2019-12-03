pub const Instruction = struct {
    /// Primary opcode
    po: u8,
    prefix: bool = false,
    name: []const u8,
    args: []const Arg,
    size: u64,
};

pub const Register = enum {
    eax,
    edi,
    edx,
    esi,
};

pub const Arg = union(enum) {
    register: Register,
    immediate,
};

pub const instructions = [_]Instruction{
    .{
        .name = "mov",
        .po = 0xb8,
        .args = &[_]Arg{
            .{ .register = .eax },
            .immediate,
        },
        .size = 5,
    },
    .{
        .name = "mov",
        .po = 0xbf,
        .args = &[_]Arg{
            .{ .register = .edi },
            .immediate,
        },
        .size = 5,
    },
    .{
        .name = "mov",
        .po = 0xbe,
        .args = &[_]Arg{
            .{ .register = .esi },
            .immediate,
        },
        .size = 5,
    },
    .{
        .name = "mov",
        .po = 0xba,
        .args = &[_]Arg{
            .{ .register = .edx },
            .immediate,
        },
        .size = 5,
    },
    .{
        .name = "syscall",
        .po = 0xba,
        .prefix = true,
        .args = &[_]Arg{},
        .size = 2,
    },
    .{
        .name = "xor",
        .po = 0x31,
        .args = &[_]Arg{
            .{ .register = .edi },
            .{ .register = .edi },
        },
        .size = 2,
    },
};
