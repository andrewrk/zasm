const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("zasm", "src/main.zig");
    exe.setBuildMode(mode);
    exe.install();

    const test_step = b.addTest("src/main.zig");
    const test_cmd = b.step("test", "Run the tests");
    test_cmd.dependOn(&test_step.step);
}
