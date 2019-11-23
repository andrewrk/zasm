pub const Instruction = struct {
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
    register,
    immediate,
};

pub const instructions = [_]Instruction{
    .{
        .name = "mov",
        .args = &[_]Arg{
            .register,
            .immediate,
        },
        .size = 5,
    },
    .{
        .name = "syscall",
        .args = &[_]Arg{},
        .size = 2,
    },
    .{
        .name = "xor",
        .args = &[_]Arg{
            .register,
            .register,
        },
        .size = 2,
    },
};
